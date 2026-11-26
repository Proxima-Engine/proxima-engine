# Capacity and horizontal scaling

## No product-level tenant ceiling

Proxima Engine does not define a maximum number of registered tenants. Tenant cardinality is a workload and storage question, not a fixed product tier or a constant in the Engine. A customer can distribute tenant assignments across as many independently provisioned Engine nodes and database targets as its infrastructure supports.

Do not confuse these separate quantities:

- **Registered tenants:** tenant identities and bindings stored by the control plane.
- **Active tenants:** tenants sending requests during a measurement window.
- **Concurrent client sessions:** open application-to-Engine TCP/database-protocol sessions.
- **Concurrent transactions/operations:** work actually executing against an upstream database.
- **Engine nodes:** independently provisioned Engine processes with separate node identities and resource budgets.

A 50,000-tenant test does not imply 50,000 simultaneous sessions. Record each quantity independently. A 50,000-session test must explicitly hold 50,000 live client sessions at the Engine ingress.

## Per-process admission and capacity

`PROXIMA_MAX_CONNECTIONS` is a per-Engine-process admission limit, not a tenant limit and not a fleet-wide limit. The default PostgreSQL listener admission limit is 4,096. Set it explicitly for each deployment after measuring CPU, memory, file descriptors, network capacity, TLS cost, provider runtime cost and expected session lifetime.

The PostgreSQL wire listener currently uses fail-fast admission when all connection permits are occupied: excess connections are rejected and counted rather than accumulating in an unbounded in-process queue. This protects the process from unbounded socket/task growth. Clients should use bounded retry with jitter and an application deadline; do not retry in a tight loop.

For a target of 50,000 simultaneous client sessions, a 4,096-session node budget requires at least 13 nodes for raw arithmetic capacity (12 nodes provide only 49,152). Use additional node headroom so the fleet can still carry the target after a node is drained or lost. This is a planning example, not a performance claim: actual per-node capacity must be benchmarked on the customer's hardware.

## PostgreSQL pooling and tenant-role cardinality

The development PgBouncer profile uses transaction pooling and separate tenant-role pool identities. Its per-user pool size must stay small because the number of possible user/database pools grows with tenant count.

The default local development configuration now:
- accepts up to 4,096 client sockets per PgBouncer process;
- limits each configured PgBouncer database alias to 64 upstream server connections;
- limits one tenant user to four upstream server connections;
- bounds the wait for a server connection to 30 seconds.

The database-wide limit is scoped to a PgBouncer database alias, not to an arbitrary physical PostgreSQL cluster across multiple aliases or PgBouncer instances. If several aliases or pooler instances reach the same PostgreSQL cluster, allocate a shared connection budget across them and enforce it at the database/cluster operations layer. Leave PostgreSQL administrative, replication, monitoring and failover connection headroom outside the application pool budget.

Do not raise `default_pool_size` in proportion to tenant count. With tenant-specific PostgreSQL roles, a pool size of two across tens of thousands of active tenant identities can still create a very large theoretical server-connection demand. Keep the per-alias cap authoritative and observe `SHOW POOLS`, `SHOW DATABASES`, `SHOW USERS`, waiting clients, active/idle server connections and query wait time.

PgBouncer's `max_client_conn` is per process. Its file-descriptor demand can exceed that value because server sockets are additional. Raise container/OS file-descriptor limits deliberately and verify them from inside the running container. A 50,000-client setting is not evidence that the host can sustain 50,000 live sockets. The optional `.env.scale.example` selects `pgbouncer.scale.ini`; copy it to `.env` only when intentionally running the high-concurrency profile. The Compose profile raises the container nofile limit to 200,000, but Docker Desktop host limits and available memory/CPU still apply. The high-concurrency profile is not the default laptop profile.

## Fleet topology and node identity

Each Engine process must have its own enrolled node identity, persistent identity file, state volume, signing credential and health lifecycle. Never clone a running node's identity file or share one enrollment token between nodes. Enroll each node independently.

For multiple nodes:
1. Place a customer-managed L4 TCP load balancer in front of the Engine listener for each compatible protocol/runtime pool.
2. Use active health checks and stop sending new sessions to a node before maintenance.
3. Drain existing sessions with a bounded deadline; do not terminate active tenant transactions without an explicit failure policy.
4. Remove unhealthy nodes from new-session routing and restore them only after readiness and provider checks pass.
5. Keep node-specific credentials and tenant configuration isolated. A target assignment must land only on a node advertising the required provider capability.
6. Ensure the load balancer preserves the client protocol and does not rewrite tenant identity or startup metadata.

Cloud node enrollment, signed heartbeats, capability reporting and desired/applied configuration reconciliation manage fleet state. They do not themselves constitute a TCP data-plane load balancer. The customer's L4 ingress or orchestrator must perform connection routing and draining. Do not infer traffic distribution from a node showing healthy in Cloud.

## Provider-specific listener budgets

The Engine exposes separate per-process session caps for its native protocol gateways:

| Provider listener | Environment variable | Current default |
|---|---|---:|
| PostgreSQL wire | `PROXIMA_MAX_CONNECTIONS` | 4,096 |
| MySQL | `PROXIMA_MYSQL_MAX_CONNECTIONS` | 128 |
| MongoDB | `PROXIMA_MONGODB_MAX_CONNECTIONS` | 256 |
| Redis RESP2 | `PROXIMA_REDIS_MAX_CONNECTIONS` | 128 |
| SQL Server TDS | `PROXIMA_SQLSERVER_TDS_MAX_CONNECTIONS` | 128 |

These are per-process session admission limits, not tenant caps or a shared fleet budget. The MySQL, MongoDB, Redis and SQL Server gateway paths are protocol proxies; do not assume they multiplex many client sessions onto a smaller upstream pool. For those paths, each accepted session may consume an upstream connection. Configure the cap against the real provider's connection budget and verify observed upstream session counts. The 50,000-client environment example sets these provider caps to 50,000 for deliberate stress work; it is not a recommended production setting for a database that cannot sustain that many server sessions.

## Other database providers

PgBouncer applies only to PostgreSQL. MySQL/MariaDB, MongoDB, Redis, SQL Server, Oracle, Cassandra, CockroachDB, DynamoDB, SQLite and Elasticsearch/OpenSearch require their own provider-aware pool, session, identity and quota controls. The PostgreSQL HAProxy template is at `deploy/haproxy/engine-tcp.cfg`; its deployment contract is documented in `deploy/haproxy/README.md`. Apply the same fleet principles, but size and validate each provider runtime separately. Do not claim one PostgreSQL pool setting governs the universal database platform.

## Capacity measurement checklist

Record, at minimum:
- registered tenants, active tenants and tenant distribution per node;
- open client sessions and accepted/rejected connections per node;
- in-flight operations and transactions;
- Engine CPU, resident memory, task count, file descriptors and network throughput;
- pooler client/server sockets, per-pool and aggregate waiters, pool saturation and wait time;
- upstream database active sessions, connection rejections, locks, query latency and resource saturation;
- node health transitions, drain duration, recovery time and traffic redistribution;
- tenant-isolation denials and any unexpected cross-tenant result.

Do not publish a capacity number until the exact workload, hardware, software versions, topology, run duration, warm-up, failure conditions and raw measurements are recorded. A passing 50,000-tenant catalogue test and a passing 50,000-concurrent-session test are different claims.
