#!/usr/bin/env python3
"""Prepare Cargo.toml for crates.io publish. Removes elara-transport (not on crates.io)."""
import re
import sys
from pathlib import Path

def main():
    root = Path(__file__).parent.parent
    toml = root / "Cargo.toml"
    content = toml.read_text(encoding="utf-8")

    # Remove elara-transport dependency block (any # comments + dep line)
    content = re.sub(
        r'# [^\n]*ELARA[^\n]*\n(?:#[^\n]*\n)*elara-transport = \{ path = "elara/crates/elara-transport", optional = true \}\s*\n',
        '', content
    )

    # Update features
    content = content.replace('elara-transport = ["dep:elara-transport"]', 'elara-transport = []')
    content = content.replace('elara = ["elara-transport", "tokio"]', 'elara = ["tokio"]')
    # Ensure elara-transport = [] exists (for cfg, never enabled in publish build)
    if 'elara-transport = []' not in content:
        content = content.replace('elara = ["tokio"]', 'elara = ["tokio"]\nelara-transport = []')

    toml.write_text(content, encoding="utf-8")
    print("Cargo.toml prepared for publish (elara-transport removed)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
