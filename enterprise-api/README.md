# B4AE Enterprise API

Minimal REST API for Enterprise Control Plane MVP.

## Endpoints

- `GET /health` — Health check
- `GET /audit/events?limit=50&offset=0` — Audit events (MVP: empty; production: DB)

## Run

```bash
cargo run --manifest-path enterprise-api/Cargo.toml
```

Listens on `http://0.0.0.0:3000`.

## License

MIT OR Apache-2.0
