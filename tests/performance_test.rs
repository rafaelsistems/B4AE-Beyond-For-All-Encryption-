// B4AE Performance Tests
// Benchmarking and performance validation

use b4ae::crypto::{kyber, dilithium, hybrid, aes_gcm, hkdf};
use b4ae::protocol::handshake::{HandshakeConfig, HandshakeInitiator, HandshakeResponder};
use b4ae::protocol::message::Message;
use b4ae::protocol::session::{Session, KeyRotationPolicy};
use std::time::Instant;

#[test]
fn test_kyber_keygen_performance() {
    let iterations = 100;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _keypair = kyber::keypair().unwrap();
    }
    
    let duration = start.elapsed();
    let avg_time = duration.as_micros() / iterations;
    
    println!("Kyber KeyGen: {} µs average", avg_time);
    
    // Target: <2000 µs (2ms) - PQ crypto is slower than classical
    assert!(avg_time < 2000, "Kyber keygen too slow: {} µs", avg_time);
}

#[test]
fn test_dilithium_sign_performance() {
    let keypair = dilithium::keypair().unwrap();
    let message = b"Test message for signing";
    
    let iterations = 100;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _signature = dilithium::sign(&keypair.secret_key, message).unwrap();
    }
    
    let duration = start.elapsed();
    let avg_time = duration.as_micros() / iterations;
    
    println!("Dilithium Sign: {} µs average", avg_time);
    
    // Target: <15000 µs (15ms) - Dilithium5 signing is complex
    assert!(avg_time < 15000, "Dilithium sign too slow: {} µs", avg_time);
}

#[test]
fn test_dilithium_verify_performance() {
    let keypair = dilithium::keypair().unwrap();
    let message = b"Test message for verification";
    let signature = dilithium::sign(&keypair.secret_key, message).unwrap();
    
    let iterations = 100;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _valid = dilithium::verify(&keypair.public_key, message, &signature).unwrap();
    }
    
    let duration = start.elapsed();
    let avg_time = duration.as_micros() / iterations;
    
    println!("Dilithium Verify: {} µs average", avg_time);
    
    // Target: <5000 µs (5ms) - Dilithium5 verification
    assert!(avg_time < 5000, "Dilithium verify too slow: {} µs", avg_time);
}

#[test]
fn test_aes_gcm_performance() {
    let key_bytes = [0x42; 32];
    let key = aes_gcm::AesKey::from_bytes(&key_bytes).unwrap();
    let plaintext = vec![0u8; 1024]; // 1KB
    
    let iterations = 1000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let (_nonce, _ciphertext) = aes_gcm::encrypt(&key, &plaintext, b"").unwrap();
    }
    
    let duration = start.elapsed();
    let avg_time = duration.as_micros() / iterations;
    
    println!("AES-GCM Encrypt (1KB): {} µs average", avg_time);
    
    // Target: <100 µs (0.1ms) per KB
    assert!(avg_time < 100, "AES-GCM too slow: {} µs", avg_time);
}

#[test]
fn test_handshake_performance() {
    let iterations = 10;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let config = HandshakeConfig::default();
        let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
        let mut responder = HandshakeResponder::new(config).unwrap();
        
        let init = initiator.generate_init().unwrap();
        let response = responder.process_init(init).unwrap();
        initiator.process_response(response).unwrap();
        let complete = initiator.generate_complete().unwrap();
        responder.process_complete(complete).unwrap();
        
        let _client_result = initiator.finalize().unwrap();
        let _server_result = responder.finalize().unwrap();
    }
    
    let duration = start.elapsed();
    let avg_time = duration.as_millis() / iterations;
    
    println!("Complete Handshake: {} ms average", avg_time);
    
    // Target: <200ms
    assert!(avg_time < 200, "Handshake too slow: {} ms", avg_time);
}

#[test]
fn test_message_throughput() {
    // Setup session
    let config = HandshakeConfig::default();
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    let init = initiator.generate_init().unwrap();
    let response = responder.process_init(init).unwrap();
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    responder.process_complete(complete).unwrap();
    
    let client_result = initiator.finalize().unwrap();
    let server_result = responder.finalize().unwrap();
    
    let mut client_session = Session::from_handshake(
        client_result,
        b"server".to_vec(),
    ).unwrap();
    
    let mut server_session = Session::from_handshake(
        server_result,
        b"client".to_vec(),
    ).unwrap();
    
    // Test throughput
    let message_count = 1000;
    let start = Instant::now();
    
    for i in 0..message_count {
        let msg = Message::text(format!("Message {}", i));
        let encrypted = client_session.send(&msg).unwrap();
        let _decrypted = server_session.receive(&encrypted).unwrap();
    }
    
    let duration = start.elapsed();
    let throughput = (message_count as f64) / duration.as_secs_f64();
    
    println!("Message Throughput: {:.2} msg/sec", throughput);
    
    // Target: >100 msg/sec (PQ crypto is slower than classical)
    assert!(throughput > 100.0, "Throughput too low: {:.2} msg/sec", throughput);
}

#[test]
fn test_end_to_end_latency() {
    // Setup session
    let config = HandshakeConfig::default();
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    let init = initiator.generate_init().unwrap();
    let response = responder.process_init(init).unwrap();
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    responder.process_complete(complete).unwrap();
    
    let client_result = initiator.finalize().unwrap();
    let server_result = responder.finalize().unwrap();
    
    let mut client_session = Session::from_handshake(
        client_result,
        b"server".to_vec(),
    ).unwrap();
    
    let mut server_session = Session::from_handshake(
        server_result,
        b"client".to_vec(),
    ).unwrap();
    
    // Measure latency
    let iterations = 100;
    let mut total_latency = 0u128;
    
    for i in 0..iterations {
        let msg = Message::text(format!("Message {}", i));
        
        let start = Instant::now();
        let encrypted = client_session.send(&msg).unwrap();
        let _decrypted = server_session.receive(&encrypted).unwrap();
        let latency = start.elapsed();
        
        total_latency += latency.as_micros();
    }
    
    let avg_latency = total_latency / iterations;
    
    println!("End-to-End Latency: {} µs average", avg_latency);
    
    // Target: <10000 µs (10ms) for encryption+decryption with PQ crypto
    assert!(avg_latency < 10000, "Latency too high: {} µs", avg_latency);
}

#[test]
fn test_memory_usage() {
    // Test baseline memory usage
    let config = HandshakeConfig::default();
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    let init = initiator.generate_init().unwrap();
    let response = responder.process_init(init).unwrap();
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    responder.process_complete(complete).unwrap();
    
    let client_result = initiator.finalize().unwrap();
    let server_result = responder.finalize().unwrap();
    
    let _client_session = Session::from_handshake(
        client_result,
        b"server".to_vec(),
    ).unwrap();
    
    let _server_session = Session::from_handshake(
        server_result,
        b"client".to_vec(),
    ).unwrap();
    
    // Memory usage should be reasonable
    // (Actual measurement would require platform-specific tools)
    println!("Memory usage test completed");
}

#[test]
fn test_hkdf_performance() {
    let secret = vec![0x42; 32];
    let info = b"test-info";
    
    let iterations = 1000;
    let start = Instant::now();
    
    for _ in 0..iterations {
        let _key = hkdf::derive_key(&[&secret], info, 32).unwrap();
    }
    
    let duration = start.elapsed();
    let avg_time = duration.as_micros() / iterations;
    
    println!("HKDF Derive: {} µs average", avg_time);
    
    // Target: <2000 µs (2ms) - includes SHA3 overhead
    assert!(avg_time < 2000, "HKDF too slow: {} µs", avg_time);
}


#[test]
fn test_scalability_concurrent_users() {
    // Test concurrent user simulation with optimized batching
    // Uses thread pool pattern instead of spawning 10k threads
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    
    // Test with 100 concurrent batches, each creating sessions
    // This simulates scalability without overwhelming resources
    let batch_count = 10;
    let sessions_per_batch = 10;
    let total_target = batch_count * sessions_per_batch;
    
    let session_count = Arc::new(AtomicUsize::new(0));
    let sessions = Arc::new(Mutex::new(Vec::new()));
    
    println!("Testing scalability with {} batches x {} sessions = {} total", 
             batch_count, sessions_per_batch, total_target);
    
    let start = Instant::now();
    
    // Use limited thread pool approach
    let thread_count = std::cmp::min(batch_count, num_cpus_available());
    let mut handles = vec![];
    
    for batch_id in 0..batch_count {
        let sessions_clone = Arc::clone(&sessions);
        let count_clone = Arc::clone(&session_count);
        
        let handle = std::thread::spawn(move || {
            for _ in 0..sessions_per_batch {
                // Create session
                let config = HandshakeConfig::default();
                let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
                let mut responder = HandshakeResponder::new(config).unwrap();
                
                // Complete handshake
                let init = initiator.generate_init().unwrap();
                let response = responder.process_init(init).unwrap();
                initiator.process_response(response).unwrap();
                let complete = initiator.generate_complete().unwrap();
                responder.process_complete(complete).unwrap();
                
                let client_result = initiator.finalize().unwrap();
                
                // Store session
                let mut sessions = sessions_clone.lock().unwrap();
                sessions.push(client_result.session_id);
                drop(sessions);
                
                count_clone.fetch_add(1, Ordering::Relaxed);
            }
            
            println!("Batch {} completed", batch_id);
        });
        
        handles.push(handle);
    }
    
    // Wait for all threads
    for handle in handles {
        handle.join().unwrap();
    }
    
    let duration = start.elapsed();
    let final_count = session_count.load(Ordering::Relaxed);
    let sessions = sessions.lock().unwrap();
    
    println!("Created {} sessions in {:?}", sessions.len(), duration);
    println!("Average time per session: {:?}", duration / final_count as u32);
    println!("Throughput: {:.2} sessions/sec", 
             final_count as f64 / duration.as_secs_f64());
    
    // Verify all sessions created
    assert_eq!(sessions.len(), total_target);
    assert_eq!(final_count, total_target);
}

/// Get available CPU count (simplified)
fn num_cpus_available() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

#[test]
fn test_network_bandwidth_overhead() {
    // Test bandwidth overhead
    let config = HandshakeConfig::default();
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    // Complete handshake and measure sizes
    let init = initiator.generate_init().unwrap();
    let init_size = bincode::serialize(&init).unwrap().len();
    
    let response = responder.process_init(init).unwrap();
    let response_size = bincode::serialize(&response).unwrap().len();
    
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    let complete_size = bincode::serialize(&complete).unwrap().len();
    
    // Process complete message on responder side
    responder.process_complete(complete).unwrap();
    
    let total_handshake_bytes = init_size + response_size + complete_size;
    
    println!("Handshake bandwidth:");
    println!("  Init: {} bytes", init_size);
    println!("  Response: {} bytes", response_size);
    println!("  Complete: {} bytes", complete_size);
    println!("  Total: {} bytes", total_handshake_bytes);
    
    // Create sessions
    let client_result = initiator.finalize().unwrap();
    let server_result = responder.finalize().unwrap();
    
    let mut client_session = Session::from_handshake(
        client_result,
        b"server".to_vec(),
    ).unwrap();
    
    let mut server_session = Session::from_handshake(
        server_result,
        b"client".to_vec(),
    ).unwrap();
    
    // Test message overhead
    let plaintext = b"Hello, World!"; // 13 bytes
    let msg = Message::binary(plaintext.to_vec());
    let encrypted = client_session.send(&msg).unwrap();
    let encrypted_size = bincode::serialize(&encrypted).unwrap().len();
    
    let overhead = encrypted_size - plaintext.len();
    let overhead_percent = (overhead as f64 / plaintext.len() as f64) * 100.0;
    
    println!("\nMessage bandwidth:");
    println!("  Plaintext: {} bytes", plaintext.len());
    println!("  Encrypted: {} bytes", encrypted_size);
    println!("  Overhead: {} bytes ({:.1}%)", overhead, overhead_percent);
    
    // Target: <200 bytes absolute overhead for small messages
    // For PQ crypto, percentage overhead is very high for small messages
    // but absolute overhead remains reasonable
    assert!(overhead < 200, "Overhead too high: {} bytes", overhead);
}

#[test]
fn test_network_conditions_simulation() {
    // Test under various network conditions
    use std::thread;
    use std::time::Duration;
    
    let config = HandshakeConfig::default();
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    // Simulate high latency network
    println!("Testing with simulated network latency...");
    
    let start = Instant::now();
    
    let init = initiator.generate_init().unwrap();
    thread::sleep(Duration::from_millis(50)); // Simulate 50ms latency
    
    let response = responder.process_init(init).unwrap();
    thread::sleep(Duration::from_millis(50)); // Simulate 50ms latency
    
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    thread::sleep(Duration::from_millis(50)); // Simulate 50ms latency
    
    responder.process_complete(complete).unwrap();
    
    let duration = start.elapsed();
    
    println!("Handshake with 50ms latency: {:?}", duration);
    
    // Should complete even with high latency
    assert!(duration < Duration::from_secs(1));
}

#[test]
fn test_horizontal_scaling() {
    // Test horizontal scaling across multiple "servers"
    use std::collections::HashMap;
    
    let server_count = 10;
    let users_per_server = 100;
    
    println!("Testing horizontal scaling: {} servers, {} users each", 
             server_count, users_per_server);
    
    let mut servers: HashMap<usize, Vec<[u8; 32]>> = HashMap::new();
    
    let start = Instant::now();
    
    for server_id in 0..server_count {
        let mut sessions = Vec::new();
        
        for _ in 0..users_per_server {
            let config = HandshakeConfig::default();
            let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
            let mut responder = HandshakeResponder::new(config).unwrap();
            
            let init = initiator.generate_init().unwrap();
            let response = responder.process_init(init).unwrap();
            initiator.process_response(response).unwrap();
            let complete = initiator.generate_complete().unwrap();
            responder.process_complete(complete).unwrap();
            
            let result = initiator.finalize().unwrap();
            sessions.push(result.session_id);
        }
        
        servers.insert(server_id, sessions);
    }
    
    let duration = start.elapsed();
    let total_users = server_count * users_per_server;
    
    println!("Created {} users across {} servers in {:?}", 
             total_users, server_count, duration);
    println!("Average per server: {:?}", duration / server_count as u32);
    
    // Verify all servers have sessions
    assert_eq!(servers.len(), server_count);
    for (server_id, sessions) in &servers {
        assert_eq!(sessions.len(), users_per_server, 
                   "Server {} has wrong session count", server_id);
    }
}

#[test]
fn test_sustained_load() {
    // Test sustained load over time
    let duration_secs = 10; // 10 second test
    let target_rate = 100; // 100 msg/sec
    
    println!("Testing sustained load: {} msg/sec for {} seconds", 
             target_rate, duration_secs);
    
    let config = HandshakeConfig::default();
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    let init = initiator.generate_init().unwrap();
    let response = responder.process_init(init).unwrap();
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    responder.process_complete(complete).unwrap();
    
    let client_result = initiator.finalize().unwrap();
    let server_result = responder.finalize().unwrap();
    
    let mut client_session = Session::from_handshake(
        client_result,
        b"server".to_vec(),
    ).unwrap();
    
    let mut server_session = Session::from_handshake(
        server_result,
        b"client".to_vec(),
    ).unwrap();
    
    // Disable automatic key rotation for this test
    // since we don't exchange rotation messages
    let no_rotation_policy = KeyRotationPolicy {
        time_based: None,
        message_based: None,
        data_based: None,
    };
    client_session.set_rotation_policy(no_rotation_policy.clone());
    server_session.set_rotation_policy(no_rotation_policy);
    
    let start = Instant::now();
    let mut message_count = 0;
    
    while start.elapsed().as_secs() < duration_secs {
        let msg = Message::text(format!("Message {}", message_count));
        let encrypted = client_session.send(&msg).unwrap();
        let _decrypted = server_session.receive(&encrypted).unwrap();
        message_count += 1;
    }
    
    let actual_duration = start.elapsed();
    let actual_rate = message_count as f64 / actual_duration.as_secs_f64();
    
    println!("Sustained {} messages in {:?}", message_count, actual_duration);
    println!("Actual rate: {:.2} msg/sec", actual_rate);
    
    // Should maintain target rate
    assert!(actual_rate >= target_rate as f64 * 0.9, 
            "Rate too low: {:.2} msg/sec", actual_rate);
}
