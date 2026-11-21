# Cloud-to-Engine runtime lifecycle

## Phase One release

The Cloud-to-Engine assignment lifecycle is integrated across authenticated configuration retrieval, encrypted credential delivery, durable desired-state reconciliation, supervised gateway activation, provider health checks and signed acknowledgement.

Agata Proxima Cloud owns organization-scoped assignment intent and configuration revisions. Proxima Engine owns the data-plane runtime and is the authority for whether an assignment is actually active.

## Assignment retrieval and trust

The Engine authenticates the node configuration-pull endpoint with its enrolled node signing key. The request is domain-separated, timestamped and nonce-bound. Cloud verifies the node identity, organization ownership, signature freshness and replay protection before returning the node's assignments.

The response contains a signed configuration bundle bound to the enrolled node and organization. Credential envelopes use AES-256-GCM with associated data that binds the node ID, target ID, configuration revision and credential revision. The Engine verifies the bundle signature and identity, validates the envelope and decrypts credentials in memory.

Credential plaintext is not written to the shared desired-state document. The persisted assignment record contains non-secret routing metadata and revision state; secret material remains within the activation path.

## Runtime reconciliation

Each assignment has a durable reconciliation record containing its assignment identity, target identity, provider key, desired revision, applied revision, runtime phase and health marker.

The coordinator applies a desired revision through a controlled lifecycle:

1. Validate assignment identity, provider metadata, tenant bindings and revision monotonicity.
2. Prepare the provider-specific runtime configuration and protected identity registry.
3. Start the assigned gateway process with a loopback readiness endpoint.
4. Wait for listener readiness within the configured startup timeout.
5. Perform the provider's authenticated upstream health check.
6. Persist the applied revision only after all runtime checks succeed.
7. Send a signed Cloud acknowledgement containing the exact assignment, target and configuration revision, runtime result and error classification.

An activation failure records a bounded non-secret error, rolls back the attempted runtime and sends a signed failed acknowledgement. A downloaded or decrypted bundle alone is never treated as an applied runtime.

## Provider runtime contracts

- **PostgreSQL and CockroachDB:** use the native PostgreSQL-wire Engine runtime and their database-native role and row-level-security controls.
- **MySQL and MariaDB:** use the supervised MySQL-compatible gateway. The Engine validates the provider runtime schema, requires one client identity for each tenant binding, writes the protected identity registry with owner-only permissions, starts the packaged gateway, waits for its loopback listener and verifies authenticated upstream connectivity before acknowledging an applied state.
- **MongoDB and Redis:** retain their protocol-specific gateway and identity formats. The coordinator rejects a provider runtime that is not explicitly enabled and prepared for activation; it never substitutes a different protocol gateway.

Provider-specific feature contracts remain explicit. A restricted protocol gateway is not described as full database protocol parity, and provider-native profiles are not represented as Proxima wire gateways.

## Cloud acknowledgement and state

The Engine signs the acknowledgement over the node ID, organization ID, nonce, assignment ID, target ID, configuration revision, timestamp, status, health result and bounded error code.

Cloud accepts an acknowledgement only for the authenticated node and its current assignment revision. A successful runtime-health result advances the applied revision and target state. Failed or stale acknowledgements cannot advance the applied revision.

## Revocation and replacement

Assignment changes advance the desired revision. The Engine reconciles the replacement against the durable assignment identity and revision record. Revoked assignment state is not reusable as a new assignment identity. Runtime process ownership remains tied to the assignment so that replacement and shutdown operations target the correct child process.

## Operational signals

Operators can correlate Cloud assignment state with Engine logs and durable runtime records using the assignment ID, target ID, provider key and configuration revision. The Cloud view exposes desired/applied revision and acknowledgement timestamps. Engine logs use bounded error codes and do not include credential plaintext.

See the [Agata Proxima Phase One release record](https://github.com/Agata-Proxima/Agata-proxima/blob/main/docs/PHASE_ONE_RELEASE.md), [Cloud multi-database API](https://github.com/Agata-Proxima/Agata-proxima/blob/main/docs/cloud-multi-database-api.md), and [Cloud architecture](https://github.com/Agata-Proxima/Agata-proxima/blob/main/docs/cloud-multi-database-architecture.md).
