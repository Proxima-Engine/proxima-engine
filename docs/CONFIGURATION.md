# Configuration reference

The Engine reads settings from its process environment. Defaults and validation are implemented in [config.rs](../crates/proxima-engine/src/config.rs), [main.rs](../crates/proxima-engine/src/main.rs), [canary_probe.rs](../crates/proxima-engine/src/canary_probe.rs), and [attestation.rs](../crates/proxima-engine/src/attestation.rs).

## Core proxy and TLS

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROXIMA_LISTEN_ADDR` | `127.0.0.1:6432` | PostgreSQL client listener |
| `PROXIMA_UPSTREAM_ADDR` | `127.0.0.1:5432` | PostgreSQL server address reachable by the Engine |
| `PROXIMA_TENANT_SIGNING_KEY` | Unset | HMAC key for tenant tokens; at least 32 bytes. Prefer a secret file for customer deployments |
| `PROXIMA_TENANT_SIGNING_KEY_FILE` | Unset | Path to a mounted secret file containing the tenant HMAC key; takes precedence over the direct environment variable |
| `PROXIMA_TENANT_ROLE_PREFIX` | `proxima_tenant_` | Prefix for tenant PostgreSQL roles; ASCII letters, digits, and underscores only |
| `PROXIMA_UPSTREAM_CONNECT_TIMEOUT_MS` | `10000` | Upstream connect timeout; must be positive |
| `PROXIMA_MAX_CONNECTIONS` | `1024` | Maximum simultaneous client connections; must be positive |
| `PROXIMA_TLS_CERT_FILE` | Unset | Incoming client TLS certificate (PEM) |
| `PROXIMA_TLS_KEY_FILE` | Unset | Incoming client TLS private key (PEM); must be set with the certificate |
| `PROXIMA_TLS_REQUIRE_CLIENT` | `false` | Reject plaintext PostgreSQL clients when true; requires the certificate/key pair |
| `PROXIMA_TLS_HANDSHAKE_TIMEOUT_MS` | `10000` | Incoming TLS handshake timeout; must be positive |
| `PROXIMA_UPSTREAM_TLS_MODE` | `disable` | Upstream TLS mode: `disable` or `verify-full` |
| `PROXIMA_UPSTREAM_TLS_CA_FILE` | Unset | Trusted CA PEM file required for upstream TLS |
| `PROXIMA_UPSTREAM_TLS_SERVER_NAME` | Unset | Expected upstream hostname required by `verify-full` |
| `PROXIMA_UPSTREAM_TLS_HANDSHAKE_TIMEOUT_MS` | `10000` | Upstream TLS handshake timeout; must be positive |
| `PROXIMA_DASHBOARD_ENABLED` | `true` | Enable the embedded status page |
| `PROXIMA_DASHBOARD_LISTEN_ADDR` | `127.0.0.1:9080` | Status-page listener; it has no built-in authentication |
| `PROXIMA_METRICS_LISTEN_ADDR` | `127.0.0.1:9090` | Health and Prometheus listener |

Boolean settings accept `1`, `true`, `yes`, `on`, `0`, `false`, `no`, and `off` (case-insensitive). The status page and metrics listener should remain on loopback or a restricted private network.

## Node identity and enrollment

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROXIMA_NODE_ID` | Unset | Node UUID from a compatible control plane, or loaded from the saved identity |
| `PROXIMA_NODE_ENROLLMENT_URL` | Unset | Compatible control-plane enrollment URL |
| `PROXIMA_NODE_ENROLLMENT_TOKEN` | Unset | One-time bootstrap token; consumed during enrollment |
| `PROXIMA_NODE_IDENTITY_PATH` | Platform default | Persistent identity file path; the file contains a signing credential |
| `PROXIMA_NODE_SIGNING_KEY_HEX` | Unset | 32-byte node signing credential encoded as 64 hex characters; normally loaded from saved identity |
| `PROXIMA_ORGANIZATION_ID` | `unconfigured` | Organization label recorded in local evidence |

Supply the node ID, enrollment URL, and one-time token together. Store the resulting identity file securely and use a different path for each node. See [Node enrollment](NODE_ENROLLMENT.md).

## Attestation and evidence delivery

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROXIMA_ATTESTATION_LEDGER_PATH` | `data/proxima-attestations.jsonl` | Local hash-linked evidence ledger |
| `PROXIMA_ATTESTATION_SIGNING_KEY` | Unset | Alternative raw-byte signing key, at least 32 bytes |
| `PROXIMA_ATTESTATION_P99_OVERHEAD_MS` | Unset | Operator-supplied, finite, non-negative value required to enable hourly attestation |
| `PROXIMA_ATTESTATION_FORCE_RLS_ACTIVE` | Unset | Writes `force_rls_active=true` only when the value is exactly `true`; this is an operator assertion, not a live database check |
| `PROXIMA_ATTESTATION_INGEST_URL` | Unset | Optional HTTPS endpoint for a compatible evidence receiver |
| `PROXIMA_ATTESTATION_INGEST_TOKEN` | Unset | Optional bearer token for evidence delivery; accepted only with the expected `aga_` prefix |
| `PROXIMA_ATTESTATION_ALLOW_INSECURE_HTTP` | Unset | Explicit opt-in for the supported local Docker HTTP receiver only; do not enable for public deployments |
| `PROXIMA_BREAK_GLASS_OUTBOX_DIR` | `data/proxima-break-glass-outbox` | Durable local outbox for emergency-access events |
| `PROXIMA_BREAK_GLASS_REPLAY_DIR` | `data/proxima-break-glass-replays` | Persistent nonce store that rejects reused emergency tokens |

The attestation loop is disabled unless a valid signing credential and `PROXIMA_ATTESTATION_P99_OVERHEAD_MS` are configured. The overhead value is supplied by the operator; it is not independently benchmarked by the Engine. Use [Verification](VERIFICATION.md) to verify a ledger with the matching signing key, organization ID, and node ID.

## Security event delivery and tenant canary

The optional tenant canary runs adversarial tenant-isolation probes through a local loopback listener. It is disabled by default. Enable it only after you have provisioned the test tenant roles, database schema/table, node identity, signing key, and a compatible security-event receiver.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROXIMA_TENANT_CANARY_ENABLED` | Unset / disabled | Set to `true`, `1`, or `yes` to enable canary configuration |
| `PROXIMA_TENANT_CANARY_LOCAL_LISTEN_ADDR` | `127.0.0.1:16432` | Fixed loopback-only listener used for local canary connections |
| `PROXIMA_TENANT_CANARY_TENANTS` | Required when enabled | Comma-separated list of 2–10 unique tenant IDs |
| `PROXIMA_TENANT_CANARY_DATABASE` | `proxima_dev` | Database used by the canary connections |
| `PROXIMA_TENANT_CANARY_SCHEMA` | `proxima_security` | Test schema name |
| `PROXIMA_TENANT_CANARY_TABLE` | `canary_records` | Test table name |
| `PROXIMA_TENANT_CANARY_TENANT_COLUMN` | `tenant_id` | Column containing the tenant identifier |
| `PROXIMA_TENANT_CANARY_INTERVAL_SECONDS` | `300` | Probe interval; valid range is 60–3600 seconds |
| `PROXIMA_TENANT_CANARY_USER_<TENANT>` | Derived default | Optional PostgreSQL login override per tenant |
| `PROXIMA_TENANT_CANARY_PASSWORD_<TENANT>` | Required when enabled | PostgreSQL password per tenant; suffix is normalized to uppercase ASCII letters, digits, and underscores |
| `PROXIMA_TENANT_CANARY_ALLOW_INSECURE_HTTP` | Unset / false | Development-only opt-in for the supported local HTTP receiver |
| `PROXIMA_SECURITY_EVENT_INGEST_URL` | Required when enabled | HTTPS URL for a compatible security-event receiver |
| `PROXIMA_SECURITY_EVENT_INGEST_TOKEN` | Required when enabled | Bearer token; must start with `aga_`. Falls back to `PROXIMA_ATTESTATION_INGEST_TOKEN` |
| `PROXIMA_SECURITY_PROBE_REGISTER_URL` | Derived from event URL | Optional override for the probe registration URL |
| `PROXIMA_SECURITY_PROBE_REPORT_URL` | Derived from event URL | Optional override for the probe report URL |

When the tenant canary is enabled, it also requires `PROXIMA_NODE_ID` to be a valid enrolled UUID, `PROXIMA_NODE_SIGNING_KEY_HEX` to decode to exactly 32 bytes, and `PROXIMA_TENANT_SIGNING_KEY` to contain at least 32 bytes. Do not enable it against production data without a dedicated test schema and least-privilege test accounts.

## Security breaker

| Variable | Default | Purpose |
| --- | --- | --- |
| `PROXIMA_SECURITY_BREAKER` | `fail-closed` | Set to `off` to disable the peer-scoped violation breaker; keep enabled in normal operation |
| `PROXIMA_SECURITY_CIRCUIT_BREAKER` | Used only if the primary setting is unset | Legacy alias for `PROXIMA_SECURITY_BREAKER` |
| `PROXIMA_BREAKER_FAILURE_THRESHOLD` | `5` | Violations from a peer before blocking |
| `PROXIMA_BREAKER_WINDOW_SECONDS` | `60` | Observation window |
| `PROXIMA_BREAKER_COOLDOWN_SECONDS` | `300` | How long a blocked peer remains blocked |

## Local development example

The included [Compose profile](../compose.dev.yaml) sets loopback-only host ports and deliberately leaves tenant enforcement off for the first connectivity test. Start it with:

```bash
docker compose -f compose.dev.yaml up --build -d
```

That profile is for local development only. Before handling sensitive data, configure tenant enforcement, database roles/RLS, TLS, network restrictions, and secret storage as described in [Security](SECURITY.md) and [Deployment](DEPLOYMENT.md).
