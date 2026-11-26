# HAProxy TCP ingress for Proxima Engine

This is a Layer-4 TCP ingress template for PostgreSQL-wire Engine nodes. It distributes new TCP sessions across stable, node-specific DNS names using least-connections. The backend listener uses TCP port 6432; health checks issue an HTTP request to each node's `/healthz` endpoint on port 9090. Add one backend server line for each enrolled Engine node; there is no hard-coded node count in the product.

## Deployment contract

- Create a shared Docker network first (for example `docker network create proxima-engine`), then run `docker compose -f deploy/haproxy/compose.yaml up -d` from this directory. Attach every Engine Compose project to that same external network and give each Engine service the stable DNS alias used by its HAProxy server line. Run HAProxy and Engine nodes on the same private network.
- Publish only the HAProxy listener to application networks; keep Engine node listeners private.
- Give every Engine replica its own node ID, one-time enrollment token, persistent identity file and state volume. Never share node identity or identity storage between replicas.
- Configure the Engine's upstream target and tenant-signing material consistently through the customer's secret-management and deployment system.
- Keep backend server names stable and unique. Map each Cloud node ID to its corresponding HAProxy server name in the customer deployment executor's `targets.json`. Create the host socket directory before starting HAProxy and bind-mount it into both HAProxy and the executor; the example executor path is `/run/haproxy/admin.sock`.
- The `/healthz` check verifies Engine health, but it is not a complete provider-readiness check. The orchestrator must separately evaluate provider connectivity and capability before adding a node to service.
- The reference deployment executor can drain a node when its target has `haproxy_admin_socket`, `haproxy_backend` and `haproxy_server_name` configured. It moves that exact server to `drain`, waits for its current-session count to reach zero, then stops the Engine. A timeout keeps the node drained and leaves the Engine running.
- To return a healthy node to service, the executor's `running` action passes the Engine health check and changes its HAProxy server state back to `ready`.
- Set host/container file-descriptor and HAProxy `maxconn` limits from measured capacity. The sample `maxconn 100000` is a configurable ingress ceiling, not a performance claim.

## Important boundaries

The supplied Compose service publishes `127.0.0.1:6432` by default. Set `PROXIMA_INGRESS_BIND` to a private interface address only when remote application hosts must connect. Do not bind the database proxy listener to a public interface without an explicit firewall and network-security design.

This template routes new TCP sessions; it does not create tenant assignments, provision database credentials, or enroll nodes with Agata Proxima Cloud. Cloud node enrollment and desired/applied configuration reconciliation remain separate control-plane workflows. The customer must keep the node-ID-to-HAProxy-server mapping current when adding or retiring nodes.

This file is PostgreSQL-wire specific. MySQL, MongoDB, Redis and SQL Server require protocol-compatible listeners and separate health/connection budgets. Do not send different database protocols to this PostgreSQL listener.
