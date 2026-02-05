// B4AE Cryptographic Benchmarks
// Detailed performance benchmarking using Criterion

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use b4ae::crypto::{kyber, dilithium, aes_gcm, hkdf, hybrid};

fn bench_kyber_keygen(c: &mut Criterion) {
    c.bench_function("kyber_keygen", |b| {
        b.iter(|| {
            black_box(kyber::keypair().unwrap())
        })
    });
}

fn bench_kyber_encapsulate(c: &mut Criterion) {
    let keypair = kyber::keypair().unwrap();
    let shared_secret = vec![0x42; 32];
    
    c.bench_function("kyber_encapsulate", |b| {
        b.iter(|| {
            black_box(kyber::encapsulate(&keypair.public_key, &shared_secret).unwrap())
        })
    });
}

fn bench_kyber_decapsulate(c: &mut Criterion) {
    let keypair = kyber::keypair().unwrap();
    let shared_secret = vec![0x42; 32];
    let ciphertext = kyber::encapsulate(&keypair.public_key, &shared_secret).unwrap();
    
    c.bench_function("kyber_decapsulate", |b| {
        b.iter(|| {
            black_box(kyber::decapsulate(&keypair.secret_key, &ciphertext).unwrap())
        })
    });
}

fn bench_dilithium_keygen(c: &mut Criterion) {
    c.bench_function("dilithium_keygen", |b| {
        b.iter(|| {
            black_box(dilithium::keypair().unwrap())
        })
    });
}

fn bench_dilithium_sign(c: &mut Criterion) {
    let keypair = dilithium::keypair().unwrap();
    let message = b"Test message for signing benchmark";
    
    c.bench_function("dilithium_sign", |b| {
        b.iter(|| {
            black_box(dilithium::sign(&keypair.secret_key, message).unwrap())
        })
    });
}

fn bench_dilithium_verify(c: &mut Criterion) {
    let keypair = dilithium::keypair().unwrap();
    let message = b"Test message for verification benchmark";
    let signature = dilithium::sign(&keypair.secret_key, message).unwrap();
    
    c.bench_function("dilithium_verify", |b| {
        b.iter(|| {
            black_box(dilithium::verify(&keypair.public_key, message, &signature).unwrap())
        })
    });
}

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_encrypt");
    
    let key_bytes = [0x42; 32];
    let key = aes_gcm::AesKey::from_bytes(&key_bytes).unwrap();
    
    for size in [64, 256, 1024, 4096, 16384].iter() {
        let plaintext = vec![0u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(aes_gcm::encrypt(&key, &plaintext, b"").unwrap())
            })
        });
    }
    
    group.finish();
}

fn bench_aes_gcm_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_decrypt");
    
    let key_bytes = [0x42; 32];
    let key = aes_gcm::AesKey::from_bytes(&key_bytes).unwrap();
    
    for size in [64, 256, 1024, 4096, 16384].iter() {
        let plaintext = vec![0u8; *size];
        let (nonce, ciphertext) = aes_gcm::encrypt(&key, &plaintext, b"").unwrap();
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                black_box(aes_gcm::decrypt(&key, &nonce, &ciphertext, b"").unwrap())
            })
        });
    }
    
    group.finish();
}

fn bench_hkdf_derive(c: &mut Criterion) {
    let secret = vec![0x42; 32];
    let info = b"benchmark-info";
    
    c.bench_function("hkdf_derive_32", |b| {
        b.iter(|| {
            black_box(hkdf::derive_key(&[&secret], info, 32).unwrap())
        })
    });
}

fn bench_hybrid_keygen(c: &mut Criterion) {
    c.bench_function("hybrid_keygen", |b| {
        b.iter(|| {
            black_box(hybrid::generate_keypair().unwrap())
        })
    });
}

criterion_group!(
    benches,
    bench_kyber_keygen,
    bench_kyber_encapsulate,
    bench_kyber_decapsulate,
    bench_dilithium_keygen,
    bench_dilithium_sign,
    bench_dilithium_verify,
    bench_aes_gcm_encrypt,
    bench_aes_gcm_decrypt,
    bench_hkdf_derive,
    bench_hybrid_keygen
);

criterion_main!(benches);
