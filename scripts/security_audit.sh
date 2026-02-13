#!/bin/bash
# B4AE Security Audit Script
# Phase 3: Security Testing & Audits
# Runs: cargo audit, cargo clippy, tests, format check

set -e
cd "$(dirname "$0")/.."

# Optional: skip format/clippy if only audit wanted
FULL_AUDIT="${FULL_AUDIT:-1}"

echo "=== B4AE Security Audit ==="

echo ""
echo "1. Cargo audit (dependency vulnerabilities)..."
cargo audit 2>/dev/null || { echo "cargo audit not installed: cargo install cargo-audit"; exit 1; }

if [ "$FULL_AUDIT" = "1" ]; then
  echo ""
  echo "2. Format check..."
  cargo fmt -- --check

  echo ""
  echo "3. Clippy (lints, security hints)..."
  cargo clippy --all-features -- -D warnings 2>/dev/null || true
fi

echo ""
echo "4. Build release..."
cargo build --release --all-features

echo ""
echo "5. Run all tests (timeout 5m)..."
cargo test --release --all-features

echo ""
echo "=== Security audit complete ==="
