#!/bin/bash
# Hive build environment setup.
# No external C/C++ dependencies needed (pure Rust).
# Usage: source build_env.sh && cargo build --workspace

echo "Hive build environment ready."
echo "Rust: $(rustc --version 2>/dev/null || echo 'not found')"
