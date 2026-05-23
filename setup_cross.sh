#!/bin/bash
# Hive Colony cross-compilation setup.
# Installs toolchains for Windows and Android targets.
# Run this once before cross-compiling.
# Usage: bash setup_cross.sh [win|android|all]

set -e

install_win() {
    echo "=== Installing Windows x86_64 cross-compilation toolchain ==="
    rustup target add x86_64-pc-windows-gnu 2>/dev/null || true
    
    if ! which x86_64-w64-mingw32-gcc &>/dev/null; then
        echo "mingw-w64 not found. Attempting to install..."
        if which apt-get &>/dev/null; then
            if sudo -n true 2>/dev/null; then
                sudo apt-get install -y mingw-w64 gcc-mingw-w64-x86-64
            else
                echo "WARNING: Need sudo for apt-get install mingw-w64."
                echo "Install manually: sudo apt-get install mingw-w64 gcc-mingw-w64-x86-64"
                echo ""
                echo "Alternative: Install via conda:"
                echo "  conda install -c conda-forge mingw-w64"
            fi
        else
            echo "No apt-get available. Install mingw-w64 manually."
        fi
    else
        echo "mingw-w64 already installed ✓"
    fi
}

install_android() {
    echo "=== Installing Android cross-compilation toolchain ==="
    rustup target add aarch64-linux-android 2>/dev/null || true
    rustup target add armv7-linux-androideabi 2>/dev/null || true
    
    if [ -z "$ANDROID_NDK_HOME" ]; then
        echo "ANDROID_NDK_HOME not set."
        echo ""
        echo "To install Android NDK:"
        echo "  1. Download from: https://developer.android.com/ndk/downloads"
        echo "  2. Extract to ~/android-ndk"
        echo "  3. Add to ~/.bashrc: export ANDROID_NDK_HOME=~/android-ndk"
        echo "  4. Add to PATH: export PATH=\$PATH:\$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin"
    else
        echo "Android NDK found at: $ANDROID_NDK_HOME ✓"
    fi
}

case "${1:-all}" in
    win) install_win ;;
    android) install_android ;;
    all)
        install_win
        install_android
        ;;
    *)
        echo "Usage: $0 [win|android|all]"
        exit 1
        ;;
esac

echo ""
echo "=== Done ==="
echo "Cross-compile commands:"
echo "  source build_env.sh win    # then cargo build --release"
echo "  source build_env.sh android # then cargo build --release"
