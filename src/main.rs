use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Address, Network, PrivateKey, PublicKey};
use bitcoin::script::ScriptBuf;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::key::TweakedPublicKey;
use bitcoin::taproot::TapTweakHash;
use bip39::{Language, Mnemonic};
use clap::{Parser, Subcommand};
use rand::Rng;
use rusqlite::Connection;
use postgres::Client;
use postgres_openssl::MakeTlsConnector;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use chrono::{Utc, Local};
use std::str::FromStr;
use std::time::{Instant, Duration};
use std::sync::{Arc, Mutex, atomic::{AtomicU64, AtomicBool, Ordering}};
use std::io::{self, BufRead, Write};
use std::thread;
use crossbeam::channel::{self, Sender, Receiver};
use anyhow::{Context, Result};
use ahash::AHashSet;

// ─────────────────────────────────────────────────────────────────────────────
// ANSI colours & UI constants
// ─────────────────────────────────────────────────────────────────────────────
const RESET   : &str = "\x1b[0m";
const BOLD    : &str = "\x1b[1m";
const DIM     : &str = "\x1b[2m";
const RED     : &str = "\x1b[91m";
const GREEN   : &str = "\x1b[92m";
const YELLOW  : &str = "\x1b[93m";
const BLUE    : &str = "\x1b[94m";
const MAGENTA : &str = "\x1b[95m";
const CYAN    : &str = "\x1b[96m";
const WHITE   : &str = "\x1b[97m";
const BG_GREEN: &str = "\x1b[42m";
const BG_BLUE : &str = "\x1b[44m";

fn hline() { println!("{DIM}{}{RESET}", "─".repeat(78)); }
fn dline() { println!("{CYAN}{}{RESET}", "═".repeat(78)); }
fn blank() { println!(); }

fn label(l: &str, v: &str, color: &str) {
    println!("  {DIM}{l:<22}{RESET}{color}{v}{RESET}");
}

fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60   { return format!("{s}s"); }
    if s < 3600 { return format!("{}m {}s", s / 60, s % 60); }
    format!("{}h {}m {}s", s / 3600, (s % 3600) / 60, s % 60)
}

fn format_big(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}

fn kps(total: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs < 0.001 { 0.0 } else { total as f64 / secs }
}

// ─────────────────────────────────────────────────────────────────────────────
// Banner
// ─────────────────────────────────────────────────────────────────────────────
fn print_banner(mode: &str, sqlite: &str, pg: &str, threads: usize) {
    print!("\x1b[2J\x1b[H");
    dline();
    println!("{BOLD}{CYAN}");
    println!("  ██████╗ ████████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗  ██╗");
    println!("  ██╔══██╗╚══██╔══╝██╔════╝     ██╔════╝██╔════╝██╔══██╗████╗ ██║");
    println!("  ██████╔╝   ██║   ██║          ███████╗██║     ███████║██╔██╗██║");
    println!("  ██╔══██╗   ██║   ██║          ╚════██║██║     ██╔══██║██║╚████║");
    println!("  ██████╔╝   ██║   ╚██████╗     ███████║╚██████╗██║  ██║██║ ╚███║");
    println!("  ╚═════╝    ╚═╝    ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝");
    println!("{RESET}");
    println!("  {DIM}Bitcoin Address Scanner · BIP32/86 · All 5 Types · Multi-Threaded{RESET}");
    dline();
    blank();
    println!("  {BOLD}{WHITE}Session Configuration{RESET}");
    hline();
    label("Mode",        mode,                   YELLOW);
    label("Threads",     &threads.to_string(),   CYAN);
    label("SQLite",      sqlite,                 CYAN);
    label("Postgres",    pg,                     CYAN);
    label("Lookup",      "AHashSet (in-memory)", GREEN);
    label("DB Insert",   "Instant (in-worker)",  GREEN);  // ← new info line
    label("Started",     &Local::now().format("%Y-%m-%d %H:%M:%S").to_string(), GREEN);
    hline();
    blank();
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────
const DEFAULT_SQLITE: &str = "scanner.db";
const DEFAULT_PG    : &str = "postgresql://postgres:password@localhost:5432/scanner";

#[derive(Parser)]
#[command(author, version, about = "BTC Scanner — Optimized multi-threaded scanner")]
struct Cli {
    #[arg(long, default_value = DEFAULT_SQLITE)]
    sqlite: String,
    #[arg(long, default_value = DEFAULT_PG)]
    pg: String,
    #[arg(long, default_value_t = 0)]
    threads: usize,
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand, Clone)]
enum Mode {
    Random,
    Mnemonic {
        #[arg(short, long)]
        mnemonic: Option<String>,
        #[arg(short, long, default_value_t = 0)]
        words: usize,
        #[arg(short, long, default_value_t = 5)]
        depth: u32,
    },
    Mix {
        #[arg(short, long, default_value_t = 5)]
        depth: u32,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Address record & generation
// ─────────────────────────────────────────────────────────────────────────────
#[derive(Clone, Debug)]
struct AddrRecord {
    addr_type:       &'static str,
    address:         String,
    derivation_path: String,
    wif:             String,
    pubkey_hex:      String,
}

struct Hit {
    record:   AddrRecord,
    mnemonic: Option<String>,
}

struct LastProcessed {
    mnemonic: Option<String>,
    addresses: Vec<AddrRecord>,
}

/// Shared PostgreSQL client type alias
type PgClient = Arc<Mutex<Client>>;

/// Optimized generation: takes pre-computed PublicKey to avoid redundant EC multiplications
fn generate_single(
    pk:      &PrivateKey,
    pubkey:  &PublicKey,
    secp:    &Secp256k1<bitcoin::secp256k1::All>,
    path:    &str,
    purpose: u32,
) -> Option<AddrRecord> {
    let net = Network::Bitcoin;
    let pubkey_hex = hex::encode(pubkey.to_bytes());

    let rec = match purpose {
        44 => AddrRecord {
            addr_type: "P2PKH",
            address: Address::p2pkh(pubkey, net).to_string(),
            derivation_path: path.to_string(),
            wif: pk.to_wif(),
            pubkey_hex,
        },
        49 => {
            if !pubkey.compressed { return None; }
            let wpkh  = pubkey.wpubkey_hash()?;
            let inner = ScriptBuf::new_p2wpkh(&wpkh);
            let addr  = Address::p2sh(&inner, net).ok()?;
            AddrRecord {
                addr_type: "P2SH-P2WPKH",
                address: addr.to_string(),
                derivation_path: path.to_string(),
                wif: pk.to_wif(),
                pubkey_hex
            }
        },
        84 => {
            if !pubkey.compressed { return None; }
            let addr = Address::p2wpkh(pubkey, net).ok()?;
            AddrRecord {
                addr_type: "P2WPKH",
                address: addr.to_string(),
                derivation_path: path.to_string(),
                wif: pk.to_wif(),
                pubkey_hex
            }
        },
        86 => {
            // Internal (untweaked) x-only pubkey
            let xonly_internal = XOnlyPublicKey::from(pubkey.inner);

            // BIP-341 key-path tweak: Q = P + hash(P)·G
            let tweak = TapTweakHash::from_key_and_tweak(xonly_internal, None).to_scalar();
            let tweaked_pubkey = pubkey.inner.add_exp_tweak(secp, &tweak).ok()?;
            let xonly_tweaked  = XOnlyPublicKey::from(tweaked_pubkey);

            let addr = Address::p2tr_tweaked(
                TweakedPublicKey::dangerous_assume_tweaked(xonly_tweaked), net
            );

            AddrRecord {
                addr_type: "P2TR",
                address: addr.to_string(),
                derivation_path: path.to_string(),
                wif: pk.to_wif(),                               // internal key ✓
                pubkey_hex: hex::encode(xonly_internal.serialize()), // 32-byte x-only ✓
            }
        },
        _ => return None,
    };
    Some(rec)
}

// ─────────────────────────────────────────────────────────────────────────────
// FAST IN-MEMORY ADDRESS SET
// ─────────────────────────────────────────────────────────────────────────────
fn load_address_set(path: &str) -> Result<AHashSet<String>> {
    let conn = Connection::open(path)
        .with_context(|| format!("Cannot open SQLite: {path}"))?;

    conn.execute_batch("
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous  = NORMAL;
        PRAGMA cache_size   = -65536;
        PRAGMA mmap_size    = 268435456;
        PRAGMA temp_store   = MEMORY;
    ")?;

    let mut stmt = conn.prepare("SELECT address FROM addresses")?;
    let iter = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut set = AHashSet::new();
    for r in iter { set.insert(r?); }

    println!("  {GREEN}✔  Loaded {}{} addresses into memory{RESET}",
        BOLD, format_big(set.len() as u64));
    Ok(set)
}

// ─────────────────────────────────────────────────────────────────────────────
// Database (PostgreSQL)
// ─────────────────────────────────────────────────────────────────────────────
fn ensure_pg_table(c: &mut Client) -> Result<()> {
    c.execute(
        "CREATE TABLE IF NOT EXISTS found_addresses (
            id               SERIAL PRIMARY KEY,
            address          TEXT NOT NULL UNIQUE,
            private_key      TEXT NOT NULL,
            mnemonic         TEXT,
            derivation_path  TEXT NOT NULL,
            address_type     TEXT NOT NULL,
            created_at       TEXT NOT NULL
        )", &[]
    ).context("create table")?;
    Ok(())
}

fn insert_found(c: &mut Client, addr: &str, wif: &str,
    mnemo: Option<&str>, path: &str, atype: &str) -> Result<()>
{
    let now = Utc::now().to_rfc3339();
    c.execute(
        "INSERT INTO found_addresses
             (address, private_key, mnemonic, derivation_path, address_type, created_at)
         VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT DO NOTHING",
        &[&addr, &wif, &mnemo, &path, &atype, &now.as_str()],
    ).context("insert")?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// UI Functions
// ─────────────────────────────────────────────────────────────────────────────
fn print_found(hit: &Hit) {
    let rec = &hit.record;
    blank();
    println!("{BG_GREEN}{BOLD}  ╔══════════════════════════════════════════════════════════════════════╗{RESET}");
    println!("{BG_GREEN}{BOLD}  ║   🎯  MATCH FOUND!                                                  ║{RESET}");
    println!("{BG_GREEN}{BOLD}  ╚══════════════════════════════════════════════════════════════════════╝{RESET}");
    blank();
    label("Address",         &rec.address,         GREEN);
    label("Type",            rec.addr_type,         YELLOW);
    label("Private Key WIF", &rec.wif,              RED);
    label("Public Key",      &rec.pubkey_hex,       CYAN);
    label("Derivation Path", &rec.derivation_path,  CYAN);
    if let Some(ref m) = hit.mnemonic {
        label("Mnemonic", m, MAGENTA);
    }
    blank();
}

fn clear_status_line() {
    print!("\r\x1b[2K");
}

fn print_status_line(total: u64, hits: u64, elapsed: Duration, threads: usize) {
    let speed = kps(total, elapsed);
    let speed_str = if speed >= 1_000.0 {
        format!("{:.1}k/s", speed / 1_000.0)
    } else {
        format!("{:.0}/s", speed)
    };

    let bar_width = 20usize;
    let fill = ((total % 10_000) as usize * bar_width / 10_000).min(bar_width);
    let bar: String = format!("{GREEN}{}{RESET}{DIM}{}{}",
        "█".repeat(fill), "░".repeat(bar_width - fill), RESET);

    print!("\r  {DIM}[{RESET}{bar}{DIM}]{RESET}  \
        {BOLD}{WHITE}Scanned:{RESET} {CYAN}{:<14}{RESET}  \
        {BOLD}{WHITE}Hits:{RESET} {}{:<6}{RESET}  \
        {BOLD}{WHITE}Speed:{RESET} {YELLOW}{:<10}{RESET}  \
        {BOLD}{WHITE}Time:{RESET} {BLUE}{:<10}{RESET}  \
        {DIM}Threads: {threads}{RESET}",
        format_big(total),
        if hits > 0 { GREEN } else { DIM },
        hits,
        speed_str,
        format_duration(elapsed),
    );
    let _ = io::stdout().flush();
}

fn print_report(total: u64, hits: u64, elapsed: Duration,
    last_processed: &LastProcessed, threads: usize)
{
    clear_status_line();

    blank();
    dline();
    println!("  {BOLD}{CYAN}◈  SCAN REPORT  ◈{RESET}");
    dline();

    println!("  {BOLD}{WHITE}Statistics{RESET}");
    hline();

    label("Keys scanned",   &format_big(total),                              GREEN);
    label("Matches found",  &hits.to_string(),
          if hits > 0 { GREEN } else { DIM });
    label("Speed",          &format!("{:.1} keys/sec", kps(total, elapsed)), YELLOW);
    label("Elapsed",        &format_duration(elapsed),                       BLUE);
    label("Threads",        &threads.to_string(),                            CYAN);
    label("Timestamp",      &Local::now().format("%H:%M:%S").to_string(),    WHITE);

    blank();
    println!("  {BOLD}{WHITE}Last Processed Entity{RESET}");
    hline();

    if let Some(ref m) = last_processed.mnemonic {
        label("Mnemonic", m, YELLOW);
    } else {
        label("Mode", "Random Brute Force", YELLOW);
    }

    blank();
    println!("  {BOLD}{WHITE}Last Batch Addresses{RESET}");
    hline();

    for rec in last_processed.addresses.iter().take(5) {
        let color = match rec.addr_type {
            "P2PKH"       => BLUE,
            "P2SH-P2WPKH" => MAGENTA,
            "P2WPKH"      => GREEN,
            "P2WSH"       => YELLOW,
            "P2TR"        => CYAN,
            _             => WHITE,
        };
        let badge = format!("{BG_BLUE}{BOLD} {:<12} {RESET}", rec.addr_type);

        println!("  {badge}  {color}{}{RESET}", rec.address);
        println!("    {DIM}Path: {}{RESET}", rec.derivation_path);
        println!("    {DIM}Pub:  {}{RESET}", rec.pubkey_hex);
        println!("    {DIM}Priv: {}{RESET}", rec.wif);
    }

    if last_processed.addresses.len() > 5 {
        println!("  {DIM}  … and {} more addresses in this batch{RESET}",
            last_processed.addresses.len() - 5);
    }

    dline();
    blank();
}

// ─────────────────────────────────────────────────────────────────────────────
// Scanning helpers
// ─────────────────────────────────────────────────────────────────────────────
fn random_mnemonic(words: usize) -> Result<Mnemonic> {
    let entropy_len = if words == 24 { 32 } else { 16 };
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill(&mut entropy[..entropy_len]);
    Mnemonic::from_entropy_in(Language::English, &entropy[..entropy_len])
        .context("Failed to generate mnemonic")
}

fn mnemonic_to_seed(m: &Mnemonic) -> Vec<u8> { m.to_seed("").to_vec() }

type LastProcessedSender = Arc<Mutex<LastProcessed>>;

fn update_last_processed(
    sender:    &LastProcessedSender,
    mnemonic:  Option<String>,
    addresses: Vec<AddrRecord>,
) {
    if let Ok(mut guard) = sender.try_lock() {
        if !addresses.is_empty() {
            guard.mnemonic  = mnemonic;
            guard.addresses = addresses;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX: helper — insert to PG immediately inside the worker, then notify UI
// ─────────────────────────────────────────────────────────────────────────────
fn instant_save_and_notify(
    pg:      &PgClient,
    hit_tx:  &Sender<Hit>,
    record:  AddrRecord,
    mnemonic: Option<String>,
) {
    // 1. Write to PostgreSQL INSTANTLY — before moving to the next key
    if let Ok(ref mut client) = pg.lock() {
        if let Err(e) = insert_found(
            client,
            &record.address,
            &record.wif,
            mnemonic.as_deref(),
            &record.derivation_path,
            record.addr_type,
        ) {
            eprintln!("  {RED}[DB ERROR] Failed to insert hit: {e}{RESET}");
        }
    }

    // 2. Send to main thread for UI display only (non-blocking)
    let _ = hit_tx.send(Hit { record, mnemonic });
}

// ─────────────────────────────────────────────────────────────────────────────
// Single random key check — FIXED: instant DB insert
// ─────────────────────────────────────────────────────────────────────────────
fn run_random_check(
    secp:     &Secp256k1<bitcoin::secp256k1::All>,
    addr_set: &AHashSet<String>,
    hit_tx:   &Sender<Hit>,
    last_tx:  &LastProcessedSender,
    pg:       &PgClient,                           // ← NEW
) -> Vec<AddrRecord> {
    let mut seed = [0u8; 32];
    rand::thread_rng().fill(&mut seed);

    let sk = match SecretKey::from_slice(&seed) { Ok(k) => k, Err(_) => return vec![] };
    let pk = PrivateKey::new(sk, Network::Bitcoin);

    // Compute public key ONCE
    let pubkey = pk.public_key(secp);

    let mut recs = Vec::with_capacity(5);

    // P2PKH, P2SH-P2WPKH, P2WPKH, P2TR
    for p in [44u32, 49, 84, 86] {
        if let Some(rec) = generate_single(&pk, &pubkey, secp, "brute_force", p) {
            if addr_set.contains(&rec.address) {
                // ← FIXED: instant save + notify
                instant_save_and_notify(pg, hit_tx, rec.clone(), None);
            }
            recs.push(rec);
        }
    }

    // P2WSH
    let cs    = ScriptBuf::builder().push_key(&pubkey).push_opcode(OP_CHECKSIG).into_script();
    let addr  = Address::p2wsh(&cs, Network::Bitcoin);
    let p2wsh = AddrRecord {
        addr_type: "P2WSH",
        address: addr.to_string(),
        derivation_path: "brute_force".into(),
        wif: pk.to_wif(),
        pubkey_hex: hex::encode(pubkey.to_bytes()),
    };
    if addr_set.contains(&p2wsh.address) {
        // ← FIXED: instant save + notify
        instant_save_and_notify(pg, hit_tx, p2wsh.clone(), None);
    }
    recs.push(p2wsh);

    update_last_processed(last_tx, None, recs.clone());
    recs
}

// ─────────────────────────────────────────────────────────────────────────────
// Single mnemonic check — FIXED: instant DB insert
// ─────────────────────────────────────────────────────────────────────────────
fn run_mnemonic_check(
    secp:         &Secp256k1<bitcoin::secp256k1::All>,
    addr_set:     &AHashSet<String>,
    hit_tx:       &Sender<Hit>,
    last_tx:      &LastProcessedSender,
    fixed_phrase: &Option<String>,
    words_config: usize,
    depth:        u32,
    pg:           &PgClient,                       // ← NEW
) -> (Option<String>, Vec<AddrRecord>) {
    let (phrase, seed_vec) = if let Some(ref p) = fixed_phrase {
        let m = match Mnemonic::parse_in_normalized(Language::English, p) {
            Ok(m)  => m,
            Err(_) => return (Some(p.clone()), vec![]),
        };
        (p.clone(), mnemonic_to_seed(&m))
    } else {
        let words = if words_config == 0 {
            if rand::random() { 12 } else { 24 }
        } else {
            words_config
        };
        let m = match random_mnemonic(words) {
            Ok(m)  => m,
            Err(_) => return (None, vec![]),
        };
        let phrase = m.to_string();
        let seed   = mnemonic_to_seed(&m);
        (phrase, seed)
    };

    let master = match Xpriv::new_master(Network::Bitcoin, &seed_vec) {
        Ok(m)  => m,
        Err(_) => return (Some(phrase), vec![]),
    };

    let mut recs = Vec::new();
    for idx in 0..depth {
        for purpose in [44u32, 49, 84, 86] {
            let path_str = format!("m/{purpose}'/0'/0'/0/{idx}");
            let path  = match DerivationPath::from_str(&path_str) { Ok(p) => p, Err(_) => continue };
            let child = match master.derive_priv(secp, &path)      { Ok(c) => c, Err(_) => continue };
            let pk    = child.to_priv();

            // Compute public key ONCE
            let pubkey = pk.public_key(secp);

            if let Some(rec) = generate_single(&pk, &pubkey, secp, &path_str, purpose) {
                if addr_set.contains(&rec.address) {
                    // ← FIXED: instant save + notify
                    instant_save_and_notify(pg, hit_tx, rec.clone(), Some(phrase.clone()));
                }
                recs.push(rec);
            }
        }
    }

    update_last_processed(last_tx, Some(phrase.clone()), recs.clone());
    (Some(phrase), recs)
}

// ─────────────────────────────────────────────────────────────────────────────
// Worker thread — FIXED: receives PgClient, passes to check functions
// ─────────────────────────────────────────────────────────────────────────────
fn worker(
    mode:     Mode,
    addr_set: Arc<AHashSet<String>>,
    hit_tx:   Sender<Hit>,
    last_tx:  LastProcessedSender,
    counter:  Arc<AtomicU64>,
    running:  Arc<AtomicBool>,
    pg:       PgClient,                            // ← NEW
) {
    let secp = Secp256k1::new();

    while running.load(Ordering::Relaxed) {
        match &mode {
            Mode::Random => {
                run_random_check(&secp, &addr_set, &hit_tx, &last_tx, &pg);
                counter.fetch_add(1, Ordering::Relaxed);
            }
            Mode::Mnemonic { mnemonic, words, depth } => {
                run_mnemonic_check(
                    &secp, &addr_set, &hit_tx, &last_tx,
                    mnemonic, *words, *depth, &pg,
                );
                counter.fetch_add(1, Ordering::Relaxed);
            }
            Mode::Mix { depth } => {
                if rand::random() {
                    run_mnemonic_check(
                        &secp, &addr_set, &hit_tx, &last_tx,
                        &None, 0, *depth, &pg,
                    );
                } else {
                    run_random_check(&secp, &addr_set, &hit_tx, &last_tx, &pg);
                }
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Command listener
// ─────────────────────────────────────────────────────────────────────────────
fn start_command_thread(running: Arc<AtomicBool>) {
    thread::spawn(move || {
        let stdin = io::stdin();
        println!("  {DIM}Commands: [s]tatus  [q]uit{RESET}");
        blank();
        for line in stdin.lock().lines() {
            match line.unwrap_or_default().trim().to_lowercase().as_str() {
                "q" | "quit" | "exit" => {
                    println!("\n  {YELLOW}⟳  Shutdown requested…{RESET}");
                    running.store(false, Ordering::Relaxed);
                    break;
                }
                "s" | "status" => {
                    println!("  {DIM}(status will appear on next report interval){RESET}");
                }
                other if !other.is_empty() => {
                    println!("  {RED}Unknown command: '{other}'.  Try: s / q{RESET}");
                }
                _ => {}
            }
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// main — FIXED: pg_mutex shared to all workers
// ─────────────────────────────────────────────────────────────────────────────
fn main() -> Result<()> {
    let cli = Cli::parse();

    let num_threads = if cli.threads == 0 {
        thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
    } else {
        cli.threads
    };

    let mode_label = match &cli.mode {
        Mode::Random          => "Random (Raw Keys)",
        Mode::Mnemonic { .. } => "Mnemonic (Wallet Recovery)",
        Mode::Mix { .. }      => "Mix (Random Keys + Mnemonics)",
    };

    print_banner(mode_label, &cli.sqlite, &cli.pg, num_threads);

    print!("  {YELLOW}⟳  Loading address database…{RESET}");
    let _ = io::stdout().flush();
    let addr_set = Arc::new(load_address_set(&cli.sqlite)?);

    // TLS connector for PostgreSQL
    let mut builder = SslConnector::builder(SslMethod::tls())
        .with_context(|| "unable to create SSL connector builder")?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = MakeTlsConnector::new(builder.build());

    let mut pg = Client::connect(&cli.pg, connector)
        .with_context(|| format!("Cannot connect PostgreSQL: {}", cli.pg))?;
    ensure_pg_table(&mut pg)?;

    // ← FIXED: pg_mutex is now shared to ALL worker threads
    let pg_mutex: PgClient = Arc::new(Mutex::new(pg));

    println!("  {GREEN}✔  PostgreSQL connected{RESET}");
    println!("  {YELLOW}⟳  Spawning {num_threads} worker thread(s)…{RESET}");
    blank();

    let counter  = Arc::new(AtomicU64::new(0));
    let hits_ctr = Arc::new(AtomicU64::new(0));
    let running  = Arc::new(AtomicBool::new(true));

    let (hit_tx, hit_rx): (Sender<Hit>, Receiver<Hit>) = channel::unbounded();
    let last_processed = Arc::new(Mutex::new(LastProcessed {
        mnemonic: None,
        addresses: vec![],
    }));

    start_command_thread(Arc::clone(&running));

    let mut handles = vec![];
    for _ in 0..num_threads {
        let mode   = cli.mode.clone();
        let set    = Arc::clone(&addr_set);
        let tx     = hit_tx.clone();
        let ltx    = Arc::clone(&last_processed);
        let cnt    = Arc::clone(&counter);
        let run    = Arc::clone(&running);
        let pg_arc = Arc::clone(&pg_mutex);        // ← NEW: pass pg to each worker

        handles.push(thread::spawn(move || {
            worker(mode, set, tx, ltx, cnt, run, pg_arc)
        }));
    }
    drop(hit_tx);

    let start = Instant::now();
    let mut last_total = 0u64;

    loop {
        // ← FIXED: channel is UI-only now — DB insert already happened in worker
        while let Ok(hit) = hit_rx.try_recv() {
            hits_ctr.fetch_add(1, Ordering::Relaxed);
            print_found(&hit);
            // insert_found() is NO LONGER called here — already done instantly in worker
        }

        let total   = counter.load(Ordering::Relaxed);
        let hits    = hits_ctr.load(Ordering::Relaxed);
        let elapsed = start.elapsed();

        print_status_line(total, hits, elapsed, num_threads);

        if total / 10_000 > last_total / 10_000 && total > 0 {
            if let Ok(ref guard) = last_processed.lock() {
                print_report(total, hits, elapsed, &guard, num_threads);
            }
        }
        last_total = total;

        if !running.load(Ordering::Relaxed) { break; }
        thread::sleep(Duration::from_millis(500));
    }

    clear_status_line();
    println!("  {YELLOW}⟳  Waiting for worker threads to finish…{RESET}");
    for h in handles { let _ = h.join(); }

    let total   = counter.load(Ordering::Relaxed);
    let hits    = hits_ctr.load(Ordering::Relaxed);
    let elapsed = start.elapsed();

    blank();
    dline();
    println!("  {BOLD}{GREEN}Session Complete{RESET}");
    dline();
    label("Total Scanned", &format_big(total), GREEN);
    label("Total Hits",    &hits.to_string(),  if hits > 0 { GREEN } else { DIM });
    label("Total Time",    &format_duration(elapsed), BLUE);
    label("Avg Speed",     &format!("{:.1} keys/sec", kps(total, elapsed)), YELLOW);
    dline();
    blank();

    Ok(())
}
