FROM rust:1.85-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/mcp-oauth-proxy /usr/local/bin/
COPY config.example.toml /etc/mcp-oauth-proxy/config.toml

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/health || exit 1
ENTRYPOINT ["mcp-oauth-proxy"]
CMD ["--config", "/etc/mcp-oauth-proxy/config.toml"]
