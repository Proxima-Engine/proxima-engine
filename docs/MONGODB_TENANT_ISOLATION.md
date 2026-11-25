# MongoDB tenant isolation

## Security model

The initial supported isolation mode is **database per tenant**. Each tenant is assigned one MongoDB database and one MongoDB user whose upstream roles are scoped only to that database. Proxima binds the authenticated SCRAM username to an immutable tenant/database identity. Every admitted data command must target that exact database.

Keep MongoDB RBAC enabled as the second enforcement boundary. Assign each upstream identity a tenant-scoped database role; gateway users must not receive `root`, `readWriteAnyDatabase`, `dbAdminAnyDatabase` or other cluster-wide privileges.

MongoDB validates the SCRAM-SHA-256 exchange and performs upstream authentication. The gateway maps the authenticated principal to its tenant ID and database namespace; the identity registry contains the mapping required for that decision.

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

## Customer Docker Compose profile

The customer Compose definition includes an opt-in `mongodb` profile. It runs the dedicated MongoDB gateway executable from the same versioned runtime image as the PostgreSQL Engine and MySQL gateway.

Before starting the profile, create the secret files referenced by `compose.customer.yaml`:

- `secrets/mongodb-identities.json`: the tenant-to-database identity registry; it contains usernames and tenant/database bindings, never passwords.
- `secrets/mongodb-gateway-cert.pem` and `secrets/mongodb-gateway-key.pem`: the gateway's client-facing TLS certificate and private key.
- `secrets/mongodb-upstream-ca.pem`: the CA certificate used to verify the upstream MongoDB server certificate.
- `secrets/node_enrollment_token`: the one-time Proxima node enrollment token required by the default Engine service.
- `secrets/mysql-identities.json`: required by the optional MySQL profile definition.

Set the upstream address and TLS server name in the Compose environment file:

```dotenv
PROXIMA_MONGODB_UPSTREAM_ADDR=mongodb.internal.example:27017
PROXIMA_MONGODB_UPSTREAM_TLS=true
PROXIMA_MONGODB_UPSTREAM_TLS_SERVER_NAME=mongodb.internal.example
PROXIMA_MONGODB_BIND_ADDRESS=127.0.0.1
```

Start the gateway profile:

```bash
docker compose -f compose.customer.yaml --profile mongodb up -d --build mongodb-gateway
docker compose -f compose.customer.yaml logs -f mongodb-gateway
```

The gateway listens on `127.0.0.1:27018` by default. Keep it on loopback when the application shares the host; otherwise use a private interface, firewall rules and verified client TLS. The profile requires a verified upstream TLS CA and server name. Provision the upstream MongoDB user and tenant database with the least-privilege role described in the security model before starting the gateway.


## Wire protocol and command policy

The gateway parses MongoDB OP_MSG frames and BSON command documents. It removes speculative authentication and compression negotiation from hello messages so that commands remain inspectable. Document sequences for insert, update, and delete are decoded and included in policy validation.

The gateway uses one configured upstream address. It removes upstream replica-set topology fields from hello replies so drivers cannot discover member addresses and bypass the gateway. Configure a standalone node or a stable writable-primary endpoint; Use a stable writable-primary endpoint and set `directConnection=true` in the client URI. The gateway owns the configured upstream address and removes topology fields that could route clients around it.

The initial admitted data command set is deliberately narrow:

- find, aggregate, insert, update, delete
- count, distinct, findAndModify
- getMore, killCursors
- listCollections, listIndexes

Aggregation pipelines are inspected recursively. Cross-database lookup/union/graph traversal, output stages, JavaScript execution, change streams, server administration, user management, and unknown commands fail closed. Logical session IDs are tenant-bound, bounded, and expire after 30 minutes of inactivity. Transaction start/commit/abort commands are denied because transaction pinning and failover behavior have not passed replica-set acceptance testing. MongoDB's own user/cursor authorization remains required for cursor continuation.

## Supported command behavior

This is a restricted wire gateway, not full MongoDB server feature parity. The initial implementation supports OP_MSG only, SCRAM-SHA-256 only, and `admin` as the SCRAM authentication source. OP_QUERY, OP_COMPRESSED, OP_MSG checksums, exhaust streams, speculative authentication, SCRAM-SHA-1, PLAIN, X.509, LDAP, and unsupported commands are not admitted. Compression is intentionally not negotiated.

The command policy accepts the supported tenant CRUD and cursor operations and rejects transaction commands. The CI suite uses a real MongoDB standalone service and verifies SCRAM authentication, tenant database binding, topology-field sanitization, cross-database and aggregation denial, transaction-command rejection, database enumeration controls and cursor continuation.

## Defense in depth

- Keep one database per tenant and one least-privilege upstream MongoDB identity per tenant.
- Do not grant gateway identities cluster-wide roles.
- Keep the identity registry readable only by the gateway process.
- Require verified TLS from clients and to non-local upstream servers.
- Monitor rejected commands and authentication failures.
- Treat unsupported operations as denied, not as a reason to bypass the gateway.

## Clone, build and verify

Clone the Engine repository and enter its root:

```bash
git clone https://github.com/Proxima-Engine/proxima-engine.git
cd proxima-engine
cargo build --release -p proxima-engine --bin proxima-mongodb-gateway
bash scripts/test-mongodb-tenant-isolation-ci.sh
```

## Cloud assignment

In **Agata Proxima Cloud → Dashboard → Databases**, register the existing MongoDB service, enroll an Engine node, assign the target to that node, create the tenant binding and deploy the configuration. The Engine activates the MongoDB runtime and reports the applied revision and tenant evidence to the workspace.
