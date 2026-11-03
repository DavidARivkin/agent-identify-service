FROM rust:1-bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
COPY migrations ./migrations
COPY tests ./tests
RUN cargo build --release
RUN openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /app/dev-signing-key.pem

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser
WORKDIR /app
# Persistent data directory for DuckDB / SQLite file
RUN mkdir -p /app/data && chown 10001:10001 /app/data
COPY --from=builder /app/target/release/agent-identity-service /usr/local/bin/agent-identity-service
COPY --from=builder /app/migrations /app/migrations
COPY --from=builder --chown=10001:10001 /app/dev-signing-key.pem /app/dev-signing-key.pem
COPY --chown=10001:10001 config.example.yaml /app/config.yaml
USER 10001
ENV RUST_LOG=info
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/agent-identity-service"]
