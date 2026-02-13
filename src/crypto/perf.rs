//! Performance tuning: CPU feature detection (AES-NI, SIMD)
//!
//! B4AE uses hardware acceleration when available via aes-gcm and pqcrypto crates.
//! This module provides runtime detection for diagnostics and optional fallbacks.

/// Detect AES-NI (x86/x86_64). Returns true if hardware AES is available.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn aes_ni_available() -> bool {
    std::arch::is_x86_feature_detected!("aes")
}

/// Detect AES-NI on non-x86 (e.g. ARM). ARMv8 has crypto extensions.
#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn aes_ni_available() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

/// Detect AVX2 (x86/x86_64). Used by some SIMD optimizations.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn avx2_available() -> bool {
    std::arch::is_x86_feature_detected!("avx2")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub fn avx2_available() -> bool {
    false
}

/// Print current CPU capabilities (for diagnostics).
pub fn print_cpu_capabilities() {
    println!("B4AE CPU capabilities:");
    println!("  AES-NI / hardware AES: {}", aes_ni_available());
    println!("  AVX2: {}", avx2_available());
}
