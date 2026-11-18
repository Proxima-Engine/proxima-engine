# MySQL tenant isolation development

## Release status

The MySQL implementation is a separate Rust crate and executable. It does not modify the PostgreSQL wire-protocol proxy or enable SQLx's MySQL driver in the Control Plane.

The branch currently contains:

- A separate proxima-mysql-gateway binary and TLS listener.
- Bounded MySQL classic-protocol framing and initial handshake parsing.
- TLS-only gateway-account authentication using caching_sha2_password.
- HMAC-SHA256 tenant assertions with a one-hour maximum lifetime.
- Server-derived tenant database routing; client-selected databases are rejected.
- Verified-CA TLS connections to MySQL 8.4 using tenant-specific runtime credentials.
- A tenant-bound packet relay that rejects commands that can change database, authentication or session protocol state.
- Database-per-tenant provisioning plans with distinct runtime and migration accounts.
- An asynchronous MySQL DDL executor and append-only, fsync-backed provisioning journal.
- An AES-256-GCM encrypted local tenant registry for gateway verifiers and upstream runtime/migration credentials.
- A provisioning CLI that writes the tenant record before marking the DDL journal complete and compensates the DDL if local registration fails.

**It is still experimental and is not a production-supported database integration.** No real MySQL end-to-end gateway test or customer deployment has passed yet. The private Control Plane API, dashboard, tenant lifecycle, fleet configuration and production packaging are not integrated. Do not route customer traffic through this branch.

## Why a separate gateway

The existing Proxima Engine is a PostgreSQL protocol gateway. MySQL has a different wire protocol, handshake, authentication exchange, packet framing, command set and session lifecycle. The MySQL gateway therefore lives in crates/proxima-mysql-gateway; it does not reuse or reinterpret PostgreSQL session code.

The binaries are independent:

- PostgreSQL: cargo run -p proxima-engine
- MySQL development gateway: cargo run -p proxima-mysql-gateway
- MySQL tenant provisioning: cargo run -p proxima-mysql-gateway --bin proxima-mysql-admin -- provision <tenant-uuid> <gateway-username>

The MySQL listener defaults to 127.0.0.1:13306. It must be explicitly bound and network-restricted for any deployment. It is not automatically started by the PostgreSQL Engine executable.

## Tenant isolation model

MySQL does not provide PostgreSQL-style row-level security. Proxima will not claim that arbitrary SQL rewriting is equivalent to RLS.

The initial supported model is **one database per tenant**, with separate accounts:

- Runtime account: SELECT, INSERT, UPDATE and DELETE only, scoped to that tenant database.
- Migration account: schema-management privileges scoped to that same tenant database.
- No global grants, GRANT OPTION, account administration, FILE, SUPER, SYSTEM_USER or cross-database grants are issued to tenant accounts.
- Both accounts require TLS.
- Account host matching is exact. Wildcard host patterns are rejected.
- Revocation locks tenant accounts and removes their grants; it does not drop customer data.
- Runtime and migration credentials are distinct and stored encrypted locally.

The MySQL server's own privilege checks are the enforcement boundary. The gateway additionally binds each physical client connection to one authenticated tenant and one upstream database session. It never retargets an authenticated upstream connection to another tenant.

Shared-table multi-tenant schemas are explicitly unsupported by this model. If a customer requires multiple tenants in the same MySQL database and shared tables, this initial release must reject that topology rather than pretending it provides row-level security.

## Request path

1. The application connects to the dedicated MySQL gateway over TLS.
2. The application authenticates using a tenant-scoped gateway account and the caching_sha2_password plugin.
3. The application supplies a short-lived signed tenant assertion in the _proxima_tenant_assertion connection attribute.
4. The gateway verifies the gateway password proof, assertion signature, expiry and tenant match.
5. The gateway derives the database name and runtime username from the authenticated tenant UUID. Client-selected database names are rejected.
6. The gateway loads that tenant's runtime password from the encrypted local registry.
7. The gateway connects to the upstream MySQL server over verified TLS using that tenant's runtime account.
8. MySQL independently enforces the tenant database grants.
9. The client connection remains bound to that tenant until it closes. Missing, malformed, expired, revoked or mismatched context fails closed.

The MySQL upstream endpoint must not be reachable directly by untrusted application networks. If clients can bypass the gateway and connect with some other privileged credential, the gateway cannot enforce the intended boundary.

## Protocol support and deliberate restrictions

The gateway implements a bounded classic-protocol handshake and a packet relay. It requires TLS and currently supports the caching_sha2_password authentication plugin only. It rejects malformed, oversized and unsupported packets.

The gateway blocks COM_INIT_DB, COM_CHANGE_USER, COM_RESET_CONNECTION and COM_SET_OPTION. It does not advertise multi-statement capability. A client cannot select its database during the handshake. Prepared-statement command packets are relayed over the same tenant-bound upstream connection, but full compatibility and lifecycle behavior still require real-driver tests.

Multi-packet messages at the MySQL maximum packet boundary are not supported in this first protocol implementation. Applications that rely on very large packets or other authentication plugins are not yet supported.

The gateway does not parse arbitrary SQL to inject tenant predicates. MySQL database grants are the security boundary.

## Encrypted local registry

EncryptedTenantStore stores gateway password verifiers and tenant-specific runtime/migration credentials in one AES-256-GCM encrypted document.

Required environment variables:

- PROXIMA_MYSQL_SECRET_STORE_FILE: encrypted registry path.
- PROXIMA_MYSQL_SECRET_STORE_KEY_FILE: path to a separate 64-character hexadecimal (32-byte) key file.

On Unix, the key file must be owner-only (0600). On Windows, its directory and file ACL must restrict access to the gateway service identity and administrators. The registry file is encrypted and temporary writes use owner-only permissions on Unix.

The registry is a single-writer local store. Do not run multiple gateway processes against the same file. The key file is not stored inside the encrypted registry directory by the code and must be backed up separately. Loss of the key makes the registry unreadable. Store backups and the key separately under the customer's secret-management and recovery policy.

The encrypted registry is not yet synchronized with the hosted Control Plane. Multi-node replication, online secret rotation and remote secret-manager adapters remain release gates.

## Provisioning

The provisioning CLI creates a database and two tenant-scoped MySQL accounts. It requires a dedicated MySQL provisioning account and a verified CA certificate. Do not use the tenant runtime account for provisioning. Avoid using MySQL root outside disposable local development.

Required environment variables:

- PROXIMA_MYSQL_UPSTREAM_HOST
- PROXIMA_MYSQL_UPSTREAM_PORT (default 3306)
- PROXIMA_MYSQL_UPSTREAM_SERVER_NAME
- PROXIMA_MYSQL_UPSTREAM_CA_FILE
- PROXIMA_MYSQL_PROVISIONING_USER
- PROXIMA_MYSQL_PROVISIONING_PASSWORD
- PROXIMA_MYSQL_ACCOUNT_HOST — exact host/IP that MySQL should match for the tenant accounts; wildcard patterns are rejected
- PROXIMA_MYSQL_SECRET_STORE_FILE
- PROXIMA_MYSQL_SECRET_STORE_KEY_FILE
- PROXIMA_MYSQL_PROVISIONING_JOURNAL_FILE

Optional timeout/size variables:

- PROXIMA_MYSQL_CONNECT_TIMEOUT_MS
- PROXIMA_MYSQL_HANDSHAKE_TIMEOUT_MS
- PROXIMA_MYSQL_STATEMENT_TIMEOUT_MS
- PROXIMA_MYSQL_MAX_PACKET_SIZE

Provision a tenant from the repository root:

    cargo run -p proxima-mysql-gateway --bin proxima-mysql-admin -- provision <tenant-uuid> <gateway-username>

The CLI generates independent high-entropy runtime, migration and gateway credentials. It sends DDL only over verified TLS, persists the runtime and migration credentials in the encrypted local registry, and prints the gateway password once. The provisioning administrator password is read from the process environment and is not persisted by the gateway. Do not capture CLI output in CI logs, shell transcripts or source control.

For local-only testing, setting PROXIMA_MYSQL_ISSUE_LOCAL_ASSERTION=true allows the CLI to print a 15-minute assertion signed with PROXIMA_MYSQL_TENANT_ASSERTION_KEY. **Do not enable this in production.** Production assertions must be issued by the authenticated Control Plane; that API integration is not implemented yet.

MySQL DDL implicitly commits. The append-only journal records each operation and fsyncs every event. If the process crashes during provisioning, the tenant is blocked from automatic reprovisioning until an operator inspects the MySQL state and explicitly acknowledges reconciliation. Never delete or edit the journal to bypass this block.

## Gateway configuration

Required variables:

- PROXIMA_MYSQL_LISTEN_ADDR (default 127.0.0.1:13306)
- PROXIMA_MYSQL_TLS_CERT_FILE
- PROXIMA_MYSQL_TLS_KEY_FILE
- PROXIMA_MYSQL_UPSTREAM_HOST
- PROXIMA_MYSQL_UPSTREAM_PORT
- PROXIMA_MYSQL_UPSTREAM_SERVER_NAME
- PROXIMA_MYSQL_UPSTREAM_CA_FILE
- PROXIMA_MYSQL_TENANT_ASSERTION_KEY — exactly 64 hexadecimal characters
- PROXIMA_MYSQL_SECRET_STORE_FILE
- PROXIMA_MYSQL_SECRET_STORE_KEY_FILE

Optional variables:

- PROXIMA_MYSQL_MAX_CONNECTIONS (default 256)
- PROXIMA_MYSQL_MAX_PACKET_SIZE (default 16777214)
- PROXIMA_MYSQL_CONNECT_TIMEOUT_MS (default 10000)
- PROXIMA_MYSQL_HANDSHAKE_TIMEOUT_MS (default 10000)

Run the separate gateway:

    cargo run -p proxima-mysql-gateway

The gateway uses its own TLS certificate for client connections and a separately verified CA/server name for the upstream MySQL connection. Do not disable upstream certificate verification in production.

## Verification

From the repository root on Windows:

    .\tools\verify-mysql.ps1

This runs Rust formatting, workspace tests, Clippy and the disposable MySQL 8.4 grant-boundary smoke test. The smoke test exercises direct MySQL grants and is not a full end-to-end test of the MySQL gateway. No GitHub Actions run is required for this local workflow.

Before production support, real MySQL 8.4 tests must cover:

- MySQL client-driver compatibility and TLS handshake behavior.
- Valid/invalid gateway credentials and tenant assertions.
- Tenant A and Tenant B read/write denial in both directions.
- Prepared statements, transactions, multi-result responses and connection teardown.
- Rejection of session/database switching and unsupported protocol commands.
- Credential rotation, account revocation and existing-session termination.
- Provisioning crash recovery, ambiguous DDL outcomes and journal reconciliation.
- Definer-security views, routines and triggers.
- MySQL restart, gateway restart and encrypted-store recovery.
- Control Plane tenant lifecycle, audit, node enrollment and multi-node secret distribution.

## MySQL-specific security constraints

- Definer-security views, routines and triggers can execute with definer privileges. Their definers must be tenant-scoped and have no global privileges.
- Runtime accounts must never have DDL or account-management privileges.
- Migration accounts are for controlled schema changes only; they must not be used by application traffic.
- Existing customer databases cannot be silently adopted. Adoption requires inspection and privilege reconciliation.
- Shared-table tenant isolation, arbitrary SQL rewriting, cross-database queries, replication administration and privileged support access are outside the first release.

## Production release rule

MySQL is not advertised as supported until the Control Plane integration, customer packaging, real MySQL protocol tests and adversarial tenant-isolation tests all pass. A successful connection or generated SQL plan is not proof of tenant isolation.
