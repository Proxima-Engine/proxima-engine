# MongoDB tenant isolation

## Security model

The initial supported isolation mode is **database per tenant**. Each tenant is assigned one MongoDB database and one MongoDB user whose upstream roles are scoped only to that database. Proxima binds the authenticated SCRAM username to an immutable tenant/database identity. Every admitted data command must target that exact database.

MongoDB RBAC is a mandatory second enforcement boundary. Proxima's command policy is not a replacement for upstream privileges. Do not give gateway users `root`, `readWriteAnyDatabase`, `dbAdminAnyDatabase`, or other cluster-wide roles.

The gateway does not store user passwords. It terminates client TLS, identifies the principal from the SCRAM-SHA-256 client-first message, and forwards the SCRAM exchange to MongoDB. MongoDB verifies the password and performs authentication. The identity registry only maps usernames to tenant IDs and database names.

## Gateway executable

Build and run the dedicated binary:

```bash
cargo build -p proxima-engine --bin proxima-mongodb-gateway

export PROXIMA_MONGODB_LISTEN_ADDR=127.0.0.1:27018
export PROXIMA_MONGODB_UPSTREAM_ADDR=127.0.0.1:27017
export PROXIMA_MONGODB_IDENTITY_REGISTRY=/etc/proxima/mongodb-identities.json
export PROXIMA_MONGODB_TLS_CERT_FILE=/etc/proxima/tls/gateway-cert.pem
export PROXIMA_MONGODB_TLS_KEY_FILE=/etc/proxima/tls/gateway-key.pem

# Production default: verify upstream TLS with a configured CA and server name.
export PROXIMA_MONGODB_UPSTREAM_TLS=true
export PROXIMA_MONGODB_UPSTREAM_TLS_CA_FILE=/etc/proxima/tls/mongodb-ca.pem
export PROXIMA_MONGODB_UPSTREAM_TLS_SERVER_NAME=mongodb.internal.example

./target/release/proxima-mongodb-gateway
```

The identity registry is JSON and contains no password material:

```json
{
  "users": [
    {
      "username": "tenant_a_gateway",
      "tenant_id": "tenant-a",
      "database": "tenant_a_db",
      "auth_source": "admin"
    },
    {
      "username": "tenant_b_gateway",
      "tenant_id": "tenant-b",
      "database": "tenant_b_db",
      "auth_source": "admin"
    }
  ]
}
```

A tenant may have more than one username, but a tenant maps to exactly one database and a database cannot be assigned to multiple tenant IDs. The configured upstream MongoDB users must exist and must have least-privilege roles scoped to their assigned databases.

Connect with a normal MongoDB driver URI, pointing at the gateway and using the upstream user's credentials:

```text
mongodb://tenant_a_gateway:<password>@gateway.example:27018/tenant_a_db?authSource=admin&tls=true&directConnection=true
```

Client-to-gateway TLS is mandatory. Upstream TLS verification is enabled by default. Disabling upstream TLS is intended only for isolated local development and CI service containers.

## Wire protocol and command policy

The gateway parses MongoDB OP_MSG frames and BSON command documents. It removes speculative authentication and compression negotiation from hello messages so that commands remain inspectable. Document sequences for insert, update, and delete are decoded and included in policy validation.

The gateway uses one configured upstream address. It removes upstream replica-set topology fields from hello replies so drivers cannot discover member addresses and bypass the gateway. Configure a standalone node or a stable writable-primary endpoint; multi-host discovery and gateway-managed failover are not implemented. Client URIs must use `directConnection=true`.

The initial admitted data command set is deliberately narrow:

- find, aggregate, insert, update, delete
- count, distinct, findAndModify
- getMore, killCursors
- listCollections, listIndexes

Aggregation pipelines are inspected recursively. Cross-database lookup/union/graph traversal, output stages, JavaScript execution, change streams, server administration, user management, and unknown commands fail closed. Logical session IDs are tenant-bound, bounded, and expire after 30 minutes of inactivity. Transaction start/commit/abort commands are denied because transaction pinning and failover behavior have not passed replica-set acceptance testing. MongoDB's own user/cursor authorization remains required for cursor continuation.

## Current protocol limitations

This is a restricted wire gateway, not full MongoDB server feature parity. The initial implementation supports OP_MSG only, SCRAM-SHA-256 only, and `admin` as the SCRAM authentication source. OP_QUERY, OP_COMPRESSED, OP_MSG checksums, exhaust streams, speculative authentication, SCRAM-SHA-1, PLAIN, X.509, LDAP, and unsupported commands are not admitted. Compression is intentionally not negotiated.

Transactions, replica-set failover, and sharded-cluster behavior are not supported by this initial profile. CI uses a real MongoDB 8 standalone service and verifies SCRAM authentication, tenant database binding, topology-field sanitization, cross-database denial, cross-database aggregation denial, transaction denial, database enumeration denial at the gateway, and cursor continuation.

## Defense in depth

- Keep one database per tenant and one least-privilege upstream MongoDB identity per tenant.
- Do not grant gateway identities cluster-wide roles.
- Keep the identity registry readable only by the gateway process.
- Require verified TLS from clients and to non-local upstream servers.
- Monitor rejected commands and authentication failures.
- Treat unsupported operations as denied, not as a reason to bypass the gateway.
