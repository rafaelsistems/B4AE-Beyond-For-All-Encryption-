# B4AE Relay

Minimal UDP relay stub for B4AE Secure Relay Network.

## Run

```bash
cargo run --manifest-path b4ae-relay/Cargo.toml
```

Listens on `udp://0.0.0.0:8473`. MVP: logs packets, echoes back. Full: parse B4AE, forward.

## License

MIT OR Apache-2.0
