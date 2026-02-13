#!/usr/bin/env bash
# Prepare Cargo.toml for crates.io publish
# Removes elara-transport dependency (not on crates.io) so cargo publish succeeds.
set -e
cd "$(dirname "$0")/.."
python3 scripts/prepare_publish.py
