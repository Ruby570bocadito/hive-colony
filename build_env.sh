#!/bin/bash
# Hive Colony build environment setup.
# Pure Rust — no external C/C++ dependencies needed.
# Usage: source build_env.sh [win|android|android-arm]
#   (default) → Linux build
#   win       → Windows x86_64 cross-compile
#   android   → Android aarch64 cross-compile
#   android-arm → Android armv7 cross-compile

export OPENSSL_DIR=/usr
export OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu
export OPENSSL_INCLUDE_DIR=/usr/include

MODE="${1:-linux}"

case "$MODE" in
  win)
    export CARGO_BUILD_TARGET="x86_64-pc-windows-gnu"
    echo "Target: Windows x86_64 (mingw)"
    ;;
  android)
    export CARGO_BUILD_TARGET="aarch64-linux-android"
    echo "Target: Android aarch64"
    echo "NOTE: Requires Android NDK — set ANDROID_NDK_HOME if linker fails"
    ;;
  android-arm)
    export CARGO_BUILD_TARGET="armv7-linux-androideabi"
    echo "Target: Android armv7"
    echo "NOTE: Requires Android NDK — set ANDROID_NDK_HOME if linker fails"
    ;;
  linux|*)
    unset CARGO_BUILD_TARGET
    echo "Target: Linux x86_64 (native)"
    ;;
esac

echo "Hive Colony build environment ready."
echo "Rust: $(rustc --version 2>/dev/null || echo 'not found')"
echo "OpenSSL: ${OPENSSL_DIR} (lib: ${OPENSSL_LIB_DIR}, include: ${OPENSSL_INCLUDE_DIR})"
