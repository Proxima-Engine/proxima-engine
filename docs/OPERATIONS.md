# Proxima Engine operations

Use this guide to diagnose Engine health, database connectivity, tenant identity, runtime assignments and verification across supported provider integrations.

## First-response flow

1. Check the Engine process and health endpoint.
2. Confirm the node is enrolled and its desired configuration is current.
3. Check the assigned provider runtime, target endpoint, DNS, firewall and TLS settings.
4. Confirm the tenant identity resolves to the expected database, schema, keyspace, namespace or provider-native boundary.
5. Inspect sanitized Engine logs, metrics, audit events and the latest verification result.
6. If observed runtime differs from desired state, inspect reconciliation status before restarting or changing assignments.

## Health and status endpoints

Default local endpoints:

- Engine status page: http://127.0.0.1:9080/
- Status JSON: http://127.0.0.1:9080/api/status
- Status-page health: http://127.0.0.1:9080/health
- Metrics and health: http://127.0.0.1:9090/metrics, /health and /healthz

The status page and metrics listener do not authenticate callers. Keep them on loopback or a restricted private network. A healthy HTTP response confirms the handler is responding; it does not by itself prove every assigned provider or tenant boundary is working. Run the provider-specific verification suite as well.

## Common failures

| Symptom | Likely cause | What to check |
|---|---|---|
| Engine exits on startup | Invalid configuration, missing secret or incomplete TLS settings | Startup logs and [Configuration](CONFIGURATION.md) |
| Node is not ready | Enrollment, identity or control-plane assignment is incomplete | [Node enrollment](NODE_ENROLLMENT.md) and runtime lifecycle |
| Provider connection fails | Wrong endpoint, DNS, firewall, credentials or TLS trust | Provider target settings and the matching database guide |
| Tenant reaches the wrong resource | Incorrect tenant binding, identity mapping or provider configuration | Tenant binding, provider registry and negative isolation tests |
| Runtime does not match desired state | Reconciliation error or unavailable gateway workload | Node status, assignment revision and Kubernetes controller logs |
| Verification fails | Provider service, policy, credentials or expected isolation behavior differs | [Verification](VERIFICATION.md) and [Database production verification](DATABASE_PRODUCTION_VERIFICATION.md) |

## Provider-specific guides

- [PostgreSQL](POSTGRESQL.md)
- [MySQL](MYSQL.md)
- [MariaDB](MARIADB.md)
- [CockroachDB](COCKROACHDB_COMPATIBILITY.md)
- [MongoDB](MONGODB_TENANT_ISOLATION.md)
- [Redis](REDIS_TENANT_GATEWAY.md)
- [Microsoft SQL Server](SQLSERVER_NATIVE_TENANCY.md)
- [SQLite](SQLITE_TENANCY.md)
- [Oracle Database](ORACLE_TENANCY.md)
- [Amazon DynamoDB](DYNAMODB_TENANCY.md)
- [Apache Cassandra](CASSANDRA_TENANCY.md)
- [Elasticsearch / OpenSearch](ELASTICSEARCH_TENANCY.md)

## Safe diagnostics

- Keep management and metrics listeners private.
- Never paste API keys, tenant tokens, database passwords, private keys or customer data into issue reports.
- Do not disable TLS verification to work around a certificate error.
- Do not reuse one tenant's upstream credentials for another tenant.
- Capture the provider, runtime version, target ID, assignment revision and verification run ID when escalating an issue.
