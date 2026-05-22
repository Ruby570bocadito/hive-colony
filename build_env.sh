#!/bin/bash
# Swarm build helper — sets OpenSSL + pkg-config env vars.
# Usage: source build_env.sh && cargo build --workspace

# Auto-detect pkg-config (local install via apt download if needed)
if ! command -v pkg-config &>/dev/null; then
    if [ -x /tmp/pkgconf/usr/bin/pkgconf ]; then
        export PATH="/tmp/pkgconf/usr/bin:$PATH"
        export LD_LIBRARY_PATH="/tmp/pkgconf/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH"
        echo "pkg-config: /tmp/pkgconf (local)"
    else
        echo "WARNING: pkg-config not found. Install: apt download pkgconf pkgconf-bin libpkgconf3 && dpkg -x *.deb /tmp/pkgconf"
    fi
fi

export OPENSSL_DIR=/usr
export OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu
export OPENSSL_INCLUDE_DIR=/usr/include

echo "OpenSSL: ${OPENSSL_DIR} (lib: ${OPENSSL_LIB_DIR}, include: ${OPENSSL_INCLUDE_DIR})"
echo "pkg-config: $(command -v pkg-config || echo 'NOT FOUND')"
