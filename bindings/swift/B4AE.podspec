Pod::Spec.new do |s|
  s.name             = 'B4AE'
  s.version          = '1.0.0'
  s.summary          = 'B4AE — Quantum-safe transport layer for iOS/macOS'
  s.description      = <<-DESC
    B4AE Swift bindings for quantum-resistant encryption. Subset API: AES-256-GCM encrypt/decrypt.
    Requires libb4ae_ffi (build with scripts/build_ios.sh on macOS).
  DESC
  s.homepage         = 'https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-'
  s.license          = { :type => 'MIT', :file => '../../LICENSE-MIT' }
  s.author           = { 'B4AE Team' => 'rafaelsistems@gmail.com' }
  s.source           = { :git => 'https://github.com/rafaelsistems/B4AE-Beyond-For-All-Encryption-.git', :tag => "v#{s.version}" }
  s.swift_version    = '5.9'
  s.ios.deployment_target = '13.0'
  s.osx.deployment_target = '10.15'
  s.source_files     = 'Sources/B4AE/**/*.swift'
  s.requires_arc     = true

  # Native lib must be built separately: run scripts/build_ios.sh on macOS
  # For CocoaPods distribution, vendored binaries (libs/*.a) or XCFramework needed
  # s.vendored_libraries = 'libs/libb4ae_ffi.a'
end
