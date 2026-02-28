FROM rust:1.82-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/mcp-oauth-proxy /usr/local/bin/
COPY config.example.toml /etc/mcp-oauth-proxy/config.toml

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["mcp-oauth-proxy", "--help"]
ENTRYPOINT ["mcp-oauth-proxy"]
CMD ["--config", "/etc/mcp-oauth-proxy/config.toml"]
