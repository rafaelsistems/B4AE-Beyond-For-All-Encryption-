# B4AE Release Checklist

Checklist untuk General Availability (GA) release.

---

## Phase 4: General Availability

### Pre-Release

- [ ] All tests pass: `cargo test --all-features`
- [ ] Security audit: `./scripts/security_audit.sh`
- [ ] `cargo audit` clean
- [ ] Clippy clean: `cargo clippy --all-features -- -D warnings`
- [ ] Docs build: `cargo doc --no-deps`
- [ ] CHANGELOG.md updated
- [ ] Version bumped in Cargo.toml

### crates.io Publish

- [ ] See [CRATES_IO_PUBLISH_PREP](CRATES_IO_PUBLISH_PREP.md)
- [ ] `cargo publish --dry-run` succeeds
- [ ] Resolve elara-transport dependency (path vs crates.io)
- [ ] Publish: `cargo publish`

### GitHub Release

- [ ] Tag: `git tag v0.1.0`
- [ ] Push tag: `git push origin v0.1.0`
- [ ] Create GitHub Release with notes from CHANGELOG
- [ ] Attach artifacts (optional): binaries, SDK builds

### Post-Release

- [ ] Update README badges (crates.io, docs.rs)
- [ ] Announce (blog, social, mailing list)
- [ ] Update documentation links
- [ ] Monitor issues/feedback

### Versioning

- **Patch** (0.1.x): bug fixes, no API change
- **Minor** (0.x.0): new features, backward compatible
- **Major** (x.0.0): breaking changes

---

## Referensi

- [CRATES_IO_PUBLISH_PREP](CRATES_IO_PUBLISH_PREP.md)
- [PRODUCTION_DEPLOYMENT](PRODUCTION_DEPLOYMENT.md)
