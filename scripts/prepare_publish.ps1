# Prepare Cargo.toml for crates.io publish
# Removes elara-transport dependency (not on crates.io) so cargo publish succeeds.

$ErrorActionPreference = "Stop"
$toml = Join-Path $PSScriptRoot ".." "Cargo.toml"
$content = Get-Content $toml -Raw

# Remove elara-transport dependency and its comment block (multiline)
$content = $content -replace '(?ms)# ELARA Transport.*?elara-transport = \{ path = "elara/crates/elara-transport", optional = true \}\r?\n\r?\n', ''

# Update features
$content = $content -replace 'elara-transport = \["dep:elara-transport"\]', 'elara-transport = []'
$content = $content -replace 'elara = \["elara-transport", "tokio"\]', 'elara = ["tokio"]'

$content | Set-Content $toml -NoNewline
Write-Host "Cargo.toml prepared for publish (elara-transport removed)"
