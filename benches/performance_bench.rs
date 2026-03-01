// B4AE Performance Benchmarking Suite
// Comprehensive performance testing for optimization and validation

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use b4ae::prelude::*;
use b4ae::crypto::{CryptoConfig, SecurityLevel};
use b4ae::protocol::SecurityProfile;
use rand::Rng;

// Benchmark configuration
const MESSAGE_SIZES: &[usize] = &[64, 256, 1024, 4096, 16384, 65536];
const BATCH_SIZES: &[usize] = &[1, 10, 100, 1000];
const SECURITY_PROFILES: &[SecurityProfile] = &[
    SecurityProfile::Standard,
    SecurityProfile::High,
    SecurityProfile::Maximum,
];

/// Generate random message of specified size
fn generate_message(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen()).collect()
}

/// Setup B4AE clients for benchmarking
fn setup_clients(profile: SecurityProfile) -> (B4aeClient, B4aeClient, Vec<u8>, Vec<u8>) {
    let mut alice = B4aeClient::new(profile).unwrap();
    let mut bob = B4aeClient::new(profile).unwrap();
    
    let alice_id = b"alice_benchmark".to_vec();
    let bob_id = b"bob_benchmark".to_vec();
    
    // Perform handshake
    let init = alice.initiate_handshake(&bob_id).unwrap();
    let response = bob.respond_to_handshake(&alice_id, init).unwrap();
    let complete = alice.process_response(&bob_id, response).unwrap();
    bob.complete_handshake(&alice_id, complete).unwrap();
    alice.finalize_initiator(&bob_id).unwrap();
    
    (alice, bob, alice_id, bob_id)
}

// Cryptographic primitive benchmarks
fn bench_crypto_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_primitives");
    
    // Kyber-1024 benchmarks
    group.bench_function("kyber_keygen", |b| {
        b.iter(|| {
            b4ae::crypto::kyber::generate_keypair().unwrap()
        })
    });
    
    group.bench_function("kyber_encapsulate", |b| {
        let (pk, _) = b4ae::crypto::kyber::generate_keypair().unwrap();
        b.iter(|| {
            b4ae::crypto::kyber::encapsulate(black_box(&pk)).unwrap()
        })
    });
    
    group.bench_function("kyber_decapsulate", |b| {
        let (pk, sk) = b4ae::crypto::kyber::generate_keypair().unwrap();
        let (ct, _) = b4ae::crypto::kyber::encapsulate(&pk).unwrap();
        b.iter(|| {
            b4ae::crypto::kyber::decapsulate(black_box(&ct), black_box(&sk)).unwrap()
        })
    });
    
    // Dilithium5 benchmarks
    group.bench_function("dilithium_keygen", |b| {
        b.iter(|| {
            b4ae::crypto::dilithium::generate_keypair().unwrap()
        })
    });
    
    group.bench_function("dilithium_sign", |b| {
        let (_, sk) = b4ae::crypto::dilithium::generate_keypair().unwrap();
        let message = generate_message(1024);
        b.iter(|| {
            b4ae::crypto::dilithium::sign(black_box(&message), black_box(&sk)).unwrap()
        })
    });
    
    group.bench_function("dilithium_verify", |b| {
        let (pk, sk) = b4ae::crypto::dilithium::generate_keypair().unwrap();
        let message = generate_message(1024);
        let signature = b4ae::crypto::dilithium::sign(&message, &sk).unwrap();
        b.iter(|| {
            b4ae::crypto::dilithium::verify(black_box(&signature), black_box(&message), black_box(&pk)).unwrap()
        })
    });
    
    // AES-256-GCM benchmarks
    for size in MESSAGE_SIZES {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("aes_256_gcm_encrypt", size), size, |b, &size| {
            let key = b4ae::crypto::random::generate_random_bytes(32).unwrap();
            let nonce = b4ae::crypto::random::generate_random_bytes(12).unwrap();
            let plaintext = generate_message(size);
            b.iter(|| {
                b4ae::crypto::aes_gcm::encrypt(black_box(&key), black_box(&nonce), black_box(&plaintext), black_box(&[])).unwrap()
            })
        });
        
        group.bench_with_input(BenchmarkId::new("aes_256_gcm_decrypt", size), size, |b, &size| {
            let key = b4ae::crypto::random::generate_random_bytes(32).unwrap();
            let nonce = b4ae::crypto::random::generate_random_bytes(12).unwrap();
            let plaintext = generate_message(size);
            let ciphertext = b4ae::crypto::aes_gcm::encrypt(&key, &nonce, &plaintext, &[]).unwrap();
            b.iter(|| {
                b4ae::crypto::aes_gcm::decrypt(black_box(&key), black_box(&nonce), black_box(&ciphertext), black_box(&[])).unwrap()
            })
        });
    }
    
    // HKDF benchmarks
    group.bench_function("hkdf_derive", |b| {
        let master_secret = b4ae::crypto::random::generate_random_bytes(32).unwrap();
        b.iter(|| {
            let kdf = b4ae::crypto::hkdf::B4aeKeyDerivation::new(master_secret.clone());
            kdf.derive_all_keys().unwrap()
        })
    });
    
    group.finish();
}

// Handshake protocol benchmarks
fn bench_handshake(c: &mut Criterion) {
    let mut group = c.benchmark_group("handshake_protocol");
    
    for profile in SECURITY_PROFILES {
        let profile_name = format!("{:?}", profile);
        
        group.bench_with_input(
            BenchmarkId::new("handshake_initiation", &profile_name),
            profile,
            |b, &profile| {
                let mut alice = B4aeClient::new(profile).unwrap();
                let bob_id = b"bob".to_vec();
                
                b.iter(|| {
                    alice.initiate_handshake(black_box(&bob_id)).unwrap()
                })
            }
        );
        
        group.bench_with_input(
            BenchmarkId::new("complete_handshake", &profile_name),
            profile,
            |b, &profile| {
                let mut alice = B4aeClient::new(profile).unwrap();
                let mut bob = B4aeClient::new(profile).unwrap();
                let alice_id = b"alice".to_vec();
                let bob_id = b"bob".to_vec();
                
                b.iter(|| {
                    let init = alice.initiate_handshake(&bob_id).unwrap();
                    let response = bob.respond_to_handshake(&alice_id, init).unwrap();
                    let complete = alice.process_response(&bob_id, response).unwrap();
                    bob.complete_handshake(&alice_id, complete).unwrap();
                    alice.finalize_initiator(&bob_id).unwrap();
                })
            }
        );
    }
    
    group.finish();
}

// Message encryption/decryption benchmarks
fn bench_message_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_crypto");
    
    for profile in SECURITY_PROFILES {
        let (alice, bob, alice_id, bob_id) = setup_clients(profile);
        let profile_name = format!("{:?}", profile);
        
        for size in MESSAGE_SIZES {
            group.throughput(Throughput::Bytes(*size as u64));
            
            let message = generate_message(size);
            
            group.bench_with_input(
                BenchmarkId::new(format!("encrypt_{}", profile_name), size),
                &(&alice, &bob_id, &message),
                |b, (client, peer_id, msg)| {
                    b.iter(|| {
                        client.encrypt_message(black_box(peer_id), black_box(msg)).unwrap()
                    })
                }
            );
            
            let encrypted = alice.encrypt_message(&bob_id, &message).unwrap();
            
            group.bench_with_input(
                BenchmarkId::new(format!("decrypt_{}", profile_name), size),
                &(&bob, &alice_id, &encrypted),
                |b, (client, peer_id, encrypted_msg)| {
                    b.iter(|| {
                        client.decrypt_message(black_box(peer_id), black_box(encrypted_msg)).unwrap()
                    })
                }
            );
        }
    }
    
    group.finish();
}

// Batch processing benchmarks
fn bench_batch_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_processing");
    
    let (alice, bob, alice_id, bob_id) = setup_clients(SecurityProfile::High);
    
    for batch_size in BATCH_SIZES {
        let messages: Vec<Vec<u8>> = (0..batch_size)
            .map(|_| generate_message(1024))
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("batch_encrypt", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    for message in &messages {
                        alice.encrypt_message(&bob_id, black_box(message)).unwrap();
                    }
                })
            }
        );
        
        let encrypted_messages: Vec<Vec<u8>> = messages.iter()
            .map(|msg| alice.encrypt_message(&bob_id, msg).unwrap())
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("batch_decrypt", batch_size),
            &batch_size,
            |b, _| {
                b.iter(|| {
                    for encrypted in &encrypted_messages {
                        bob.decrypt_message(&alice_id, black_box(encrypted)).unwrap();
                    }
                })
            }
        );
    }
    
    group.finish();
}

// Key rotation benchmarks
fn bench_key_rotation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_rotation");
    
    for profile in SECURITY_PROFILES {
        let (mut alice, mut bob, alice_id, bob_id) = setup_clients(profile);
        let profile_name = format!("{:?}", profile);
        
        // Send some messages first
        for _ in 0..10 {
            let message = generate_message(1024);
            let encrypted = alice.encrypt_message(&bob_id, &message).unwrap();
            let _decrypted = bob.decrypt_message(&alice_id, &encrypted).unwrap();
        }
        
        group.bench_with_input(
            BenchmarkId::new("key_rotation", &profile_name),
            &profile,
            |b, _| {
                b.iter(|| {
                    alice.perform_key_rotation(&bob_id).unwrap();
                    bob.perform_key_rotation(&alice_id).unwrap();
                })
            }
        );
    }
    
    group.finish();
}

// Memory usage benchmarks
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");
    
    group.bench_function("client_creation", |b| {
        b.iter(|| {
            let _client = B4aeClient::new(SecurityProfile::High).unwrap();
        })
    });
    
    group.bench_function("session_establishment", |b| {
        b.iter(|| {
            let mut alice = B4aeClient::new(SecurityProfile::High).unwrap();
            let mut bob = B4aeClient::new(SecurityProfile::High).unwrap();
            
            let alice_id = b"alice".to_vec();
            let bob_id = b"bob".to_vec();
            
            let init = alice.initiate_handshake(&bob_id).unwrap();
            let response = bob.respond_to_handshake(&alice_id, init).unwrap();
            let complete = alice.process_response(&bob_id, response).unwrap();
            bob.complete_handshake(&alice_id, complete).unwrap();
            alice.finalize_initiator(&bob_id).unwrap();
        })
    });
    
    group.finish();
}

// Throughput benchmarks
fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    
    let (alice, bob, alice_id, bob_id) = setup_clients(SecurityProfile::High);
    
    // Measure messages per second
    group.throughput(Throughput::Elements(1000));
    group.bench_function("messages_per_second", |b| {
        let message = generate_message(1024);
        b.iter(|| {
            for _ in 0..1000 {
                let encrypted = alice.encrypt_message(&bob_id, &message).unwrap();
                let _decrypted = bob.decrypt_message(&alice_id, &encrypted).unwrap();
            }
        })
    });
    
    // Measure data throughput
    group.throughput(Throughput::Bytes(1024 * 1000));
    group.bench_function("data_throughput", |b| {
        let message = generate_message(1024);
        b.iter(|| {
            for _ in 0..1000 {
                let encrypted = alice.encrypt_message(&bob_id, &message).unwrap();
                let _decrypted = bob.decrypt_message(&alice_id, &encrypted).unwrap();
            }
        })
    });
    
    group.finish();
}

// Latency benchmarks
fn bench_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("latency");
    
    let (alice, bob, alice_id, bob_id) = setup_clients(SecurityProfile::High);
    
    // End-to-end latency (handshake + message)
    group.bench_function("end_to_end_latency", |b| {
        b.iter(|| {
            // Fresh clients for each iteration
            let mut alice = B4aeClient::new(SecurityProfile::High).unwrap();
            let mut bob = B4aeClient::new(SecurityProfile::High).unwrap();
            
            let alice_id = b"alice".to_vec();
            let bob_id = b"bob".to_vec();
            
            // Handshake
            let init = alice.initiate_handshake(&bob_id).unwrap();
            let response = bob.respond_to_handshake(&alice_id, init).unwrap();
            let complete = alice.process_response(&bob_id, response).unwrap();
            bob.complete_handshake(&alice_id, complete).unwrap();
            alice.finalize_initiator(&bob_id).unwrap();
            
            // Message exchange
            let message = generate_message(256);
            let encrypted = alice.encrypt_message(&bob_id, &message).unwrap();
            let _decrypted = bob.decrypt_message(&alice_id, &encrypted).unwrap();
        })
    });
    
    // Message-only latency (established session)
    group.bench_function("message_latency", |b| {
        let message = generate_message(256);
        b.iter(|| {
            let encrypted = alice.encrypt_message(&bob_id, black_box(&message)).unwrap();
            let _decrypted = bob.decrypt_message(&alice_id, black_box(&encrypted)).unwrap();
        })
    });
    
    group.finish();
}

// Scalability benchmarks
fn bench_scalability(c: &mut Criterion) {
    let mut group = c.benchmark_group("scalability");
    
    // Multiple concurrent sessions
    for session_count in &[10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("concurrent_sessions", session_count),
            session_count,
            |b, &count| {
                b.iter(|| {
                    let mut clients = Vec::new();
                    
                    // Create multiple client pairs
                    for i in 0..count {
                        let mut alice = B4aeClient::new(SecurityProfile::High).unwrap();
                        let mut bob = B4aeClient::new(SecurityProfile::High).unwrap();
                        
                        let alice_id = format!("alice_{}", i).into_bytes();
                        let bob_id = format!("bob_{}", i).into_bytes();
                        
                        let init = alice.initiate_handshake(&bob_id).unwrap();
                        let response = bob.respond_to_handshake(&alice_id, init).unwrap();
                        let complete = alice.process_response(&bob_id, response).unwrap();
                        bob.complete_handshake(&alice_id, complete).unwrap();
                        alice.finalize_initiator(&bob_id).unwrap();
                        
                        clients.push((alice, bob, alice_id, bob_id));
                    }
                    
                    // Exchange messages on all sessions
                    for (alice, bob, alice_id, bob_id) in clients {
                        let message = generate_message(1024);
                        let encrypted = alice.encrypt_message(&bob_id, &message).unwrap();
                        let _decrypted = bob.decrypt_message(&alice_id, &encrypted).unwrap();
                    }
                })
            }
        );
    }
    
    group.finish();
}

criterion_group!(
    benches,
    bench_crypto_primitives,
    bench_handshake,
    bench_message_crypto,
    bench_batch_processing,
    bench_key_rotation,
    bench_memory_usage,
    bench_throughput,
    bench_latency,
    bench_scalability
);

criterion_main!(benches);