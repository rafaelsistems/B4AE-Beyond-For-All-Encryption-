# B4AE - Production Docker Image
# Phase 4: Production Infrastructure

FROM rust:1.75-bookworm AS builder
WORKDIR /app

COPY . .

# Build B4AE with ELARA
RUN cargo build --release --example b4ae_elara_demo --features elara

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/examples/b4ae_elara_demo /usr/local/bin/

CMD ["b4ae_elara_demo"]
