#!/bin/bash
set -e  # exit on any error

# Extract package name robustly (allows leading spaces)
PACKAGE_NAME=$(grep -E '^[[:space:]]*name[[:space:]]*=' Cargo.toml | head -1 | cut -d '"' -f2)
if [ -z "$PACKAGE_NAME" ]; then
    echo "Error: Could not determine package name from Cargo.toml"
    exit 1
fi

# Create the dist folder
DIST_DIR="dist"
mkdir -p "$DIST_DIR"

echo "=== Building for native target ==="
cargo build --release
cp "target/release/$PACKAGE_NAME" "$DIST_DIR/"
echo "Copied native binary to $DIST_DIR/$PACKAGE_NAME"

echo "=== Building for Windows (x86_64-pc-windows-gnu) ==="
rustup target add x86_64-pc-windows-gnu
# Ensure mingw-w64 is installed (e.g., sudo apt install mingw-w64 on Debian/Ubuntu)
cargo build --release --target x86_64-pc-windows-gnu
cp "target/x86_64-pc-windows-gnu/release/${PACKAGE_NAME}.exe" "$DIST_DIR/${PACKAGE_NAME}-windows.exe"
echo "Copied Windows binary to $DIST_DIR/${PACKAGE_NAME}-windows.exe"

echo "=== Building for Android (aarch64-linux-android) ==="
rustup target add aarch64-linux-android

# Check if Android NDK linker is available
if command -v aarch64-linux-android21-clang &> /dev/null || [ -n "$CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER" ]; then
    cargo build --release --target aarch64-linux-android
    cp "target/aarch64-linux-android/release/$PACKAGE_NAME" "$DIST_DIR/${PACKAGE_NAME}-android"
    echo "Copied Android binary to $DIST_DIR/${PACKAGE_NAME}-android"
else
    echo "⚠️  Android NDK linker not found. Skipping Android build."
    echo "   To build for Android, install the NDK and set the linker,"
    echo "   or use 'cross' (see https://github.com/cross-rs/cross)."
fi

echo "All builds completed successfully."
echo "Binaries are saved in the '$DIST_DIR' folder:"
ls -l "$DIST_DIR"
