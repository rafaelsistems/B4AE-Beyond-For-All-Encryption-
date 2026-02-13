# B4AE Security Audit Script (Windows)
# Phase 3: Security Testing & Audits

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

Write-Host "=== B4AE Security Audit ===" -ForegroundColor Cyan

Write-Host "`n1. Cargo audit..." -ForegroundColor Yellow
cargo audit 2>$null; if ($LASTEXITCODE -ne 0) {
    Write-Host "cargo audit not installed: cargo install cargo-audit"
    exit 1
}

Write-Host "`n2. Format check..." -ForegroundColor Yellow
cargo fmt -- --check

Write-Host "`n3. Clippy..." -ForegroundColor Yellow
cargo clippy --all-features -- -D warnings

Write-Host "`n4. Build release..." -ForegroundColor Yellow
cargo build --release --all-features

Write-Host "`n5. Run tests..." -ForegroundColor Yellow
cargo test --release --all-features

Write-Host "`n=== Security audit complete ===" -ForegroundColor Green
