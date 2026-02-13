// B4AE Protocol Benchmarks
// Protocol-level performance benchmarking

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use b4ae::protocol::handshake::{HandshakeConfig, HandshakeInitiator, HandshakeResponder};
use b4ae::protocol::message::Message;
use b4ae::protocol::session::Session;

fn bench_handshake_complete(c: &mut Criterion) {
    c.bench_function("handshake_complete", |b| {
        b.iter(|| {
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
            
            black_box((client_result, server_result))
        })
    });
}

fn bench_message_send_receive(c: &mut Criterion) {
    let mut group = c.benchmark_group("message_send_receive");
    
    // Setup session once
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
        None,
    ).unwrap();
    
    let mut server_session = Session::from_handshake(
        server_result,
        b"client".to_vec(),
        None,
    ).unwrap();
    
    for size in [64, 256, 1024, 4096, 16384].iter() {
        let payload = vec![0u8; *size];
        let msg = Message::binary(payload);
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let encrypted = client_session.send(&msg).unwrap();
                let decrypted = server_session.receive(&encrypted).unwrap();
                black_box(decrypted)
            })
        });
    }
    
    group.finish();
}

fn bench_session_creation(c: &mut Criterion) {
    let config = HandshakeConfig::default();
    let mut initiator = HandshakeInitiator::new(config.clone()).unwrap();
    let mut responder = HandshakeResponder::new(config).unwrap();
    
    let init = initiator.generate_init().unwrap();
    let response = responder.process_init(init).unwrap();
    initiator.process_response(response).unwrap();
    let complete = initiator.generate_complete().unwrap();
    responder.process_complete(complete).unwrap();
    
    let client_result = initiator.finalize().unwrap();
    
    c.bench_function("session_creation", |b| {
        b.iter(|| {
            black_box(Session::from_handshake(
                client_result.clone(),
                b"server".to_vec(),
                None,
            ).unwrap())
        })
    });
}

criterion_group!(
    benches,
    bench_handshake_complete,
    bench_message_send_receive,
    bench_session_creation
);

criterion_main!(benches);
