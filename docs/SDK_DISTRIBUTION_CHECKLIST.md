# SDK Distribution Checklist

Publish B4AE SDK ke berbagai platform: CocoaPods, Maven Central, npm.

---

## Current Status

| Platform | Implementation | Publish Status |
|----------|----------------|----------------|
| Rust | crates.io | ⬜ Lihat [CRATES_IO_PUBLISH_PREP.md](CRATES_IO_PUBLISH_PREP.md) |
| iOS | bindings/swift, b4ae-ffi | ⬜ CocoaPods |
| Android | b4ae-android, JNI | ⬜ Maven Central |
| Web | b4ae-wasm | ⬜ npm |
| C FFI | b4ae-ffi | ⬜ (header + docs) |

---

## iOS (CocoaPods)

- [ ] Buat akun CocoaPods
- [ ] Validasi: `pod lib lint` atau `pod spec lint`
- [ ] Buat `.podspec` untuk B4AE Swift bindings
- [ ] Publish: `pod trunk push B4AE.podspec`
- [ ] Dokumentasi: README, API docs

---

## Android (Maven Central)

- [ ] Buat akun Sonatype / Maven Central
- [ ] GPG signing setup
- [ ] `publishToMavenLocal` test
- [ ] Publish ke Maven Central
- [ ] Group ID: `com.b4ae` atau `io.github.rafaelsistems.b4ae`

---

## Web (npm)

- [ ] Build WASM: `wasm-pack build b4ae-wasm --target web`
- [ ] Package name: `@b4ae/core` atau `b4ae-wasm`
- [ ] `npm publish`
- [ ] Dokumentasi: usage, TypeScript types jika ada

---

## C FFI (b4ae-ffi)

- [ ] cbindgen untuk header generation
- [ ] Release binary (opsional) untuk Linux/macOS/Windows
- [ ] Dokumentasi C API di docs/
- [ ] Dapat didistribusi via crates.io sebagai crate

---

## Post-Publish

- [ ] Add badges ke README (CocoaPods, Maven, npm)
- [ ] Update [README](../README.md) dengan install instructions per platform
- [ ] Announce di release notes
