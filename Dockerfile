# syntax=docker/dockerfile:1
FROM rust:1.89-slim-bookworm AS builder
WORKDIR /src

# These assets are embedded into the binary at compile time.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY vendor ./vendor
COPY dashboard ./dashboard
COPY frontend/src/assets/agata-proxima-orbit.svg ./frontend/src/assets/agata-proxima-orbit.svg

RUN cargo build --release -p proxima-engine

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 proxima \
    && useradd --system --uid 10001 --gid proxima --home-dir /var/lib/proxima --create-home proxima \
    && mkdir -p /var/lib/proxima \
    && chown -R proxima:proxima /var/lib/proxima

COPY --from=builder /src/target/release/proxima-engine /usr/local/bin/proxima-engine

ENV PROXIMA_LISTEN_ADDR=0.0.0.0:6432 \
    PROXIMA_UPSTREAM_ADDR=127.0.0.1:5432 \
    PROXIMA_DASHBOARD_ENABLED=false \
    PROXIMA_DASHBOARD_LISTEN_ADDR=127.0.0.1:9080 \
    PROXIMA_METRICS_LISTEN_ADDR=127.0.0.1:9090 \
    PROXIMA_NODE_IDENTITY_PATH=/var/lib/proxima/node-identity.json \
    PROXIMA_ATTESTATION_LEDGER_PATH=/var/lib/proxima/attestations.jsonl \
    PROXIMA_BREAK_GLASS_OUTBOX_DIR=/var/lib/proxima/break-glass-outbox \
    PROXIMA_BREAK_GLASS_REPLAY_DIR=/var/lib/proxima/replays

USER proxima:proxima
EXPOSE 6432
VOLUME ["/var/lib/proxima"]
ENTRYPOINT ["/usr/local/bin/proxima-engine"]
