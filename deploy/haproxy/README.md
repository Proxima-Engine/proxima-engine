# HAProxy TCP ingress for Proxima Engine

This is a Layer-4 TCP ingress template for PostgreSQL-wire Engine nodes. It distributes new TCP sessions across stable, node-specific DNS names using least-connections. The backend listener uses TCP port 6432; health checks issue an HTTP request to each node's `/readyz` endpoint on port 9090. Add one backend server line for each enrolled Engine node; there is no hard-coded node count in the product.

## Deployment contract

- Create the shared network once: `docker network create proxima-engine-network`.
- For each Engine node, set a unique `PROXIMA_HAPROXY_SERVER_NAME` (for example `engine-node-01`) and start it with the network overlay: `docker compose -f compose.customer.yaml -f deploy/haproxy/engine-network.override.yaml up -d`. The overlay attaches the Engine to the shared private network and binds its health listener to that network only; it does not publish port 9090.
- Start the ingress from the repository root with `docker compose -f deploy/haproxy/compose.yaml up -d`. The default external network is `proxima-engine-network`.
- Add one stable backend server line in `engine-tcp.cfg` for each Engine node and ensure the DNS name matches its `PROXIMA_HAPROXY_SERVER_NAME`.
- Publish only the HAProxy listener to application networks; keep Engine node listeners private.
- Give every Engine replica its own node ID, one-time enrollment token, persistent identity file and state volume. Never share node identity or identity storage between replicas.
- Configure the Engine's upstream target and tenant-signing material consistently through the customer's secret-management and deployment system.
- Keep backend server names stable and unique. Map each Cloud node ID to its corresponding HAProxy server name in the customer deployment executor's `targets.json`. Create both host directories before starting HAProxy (for example `sudo install -d -m 0770 /run/haproxy /var/lib/haproxy`) and bind-mount them into HAProxy and the executor. The executor uses `/run/haproxy/admin.sock` and `/var/lib/haproxy/server-state`. Restrict socket ownership and group membership to the deployment executor and HAProxy operator.
- The `/readyz` check verifies Engine health, but it is not a complete provider-readiness check. The orchestrator must separately evaluate provider connectivity and capability before adding a node to service.
- The reference deployment executor can drain a node when its target has `haproxy_admin_socket`, `haproxy_backend`, `haproxy_server_name` and `haproxy_server_state_file` configured. It moves that exact server to `drain`, persists the HAProxy server state across reloads, and waits for its current-session count to reach zero. The Engine remains running and continues its signed Cloud heartbeat while excluded from new traffic. A timeout keeps the node drained and leaves the Engine running.
- To return a healthy node to service, the executor's `running` action passes the Engine health check and changes its HAProxy server state back to `ready`, then persists that state.
- Set host/container file-descriptor and HAProxy `maxconn` limits from measured capacity. The sample `maxconn 100000` is a configurable ingress ceiling, not a performance claim.

## Important boundaries

The supplied Compose service publishes `127.0.0.1:6432` by default. Set `PROXIMA_INGRESS_BIND` to a private interface address only when remote application hosts must connect. Do not bind the database proxy listener to a public interface without an explicit firewall and network-security design.

This template routes new TCP sessions; it does not create tenant assignments, provision database credentials, or enroll nodes with Agata Proxima Cloud. Cloud node enrollment and desired/applied configuration reconciliation remain separate control-plane workflows. The customer must keep the node-ID-to-HAProxy-server mapping current when adding or retiring nodes.

This file is PostgreSQL-wire specific. MySQL, MongoDB, Redis and SQL Server require protocol-compatible listeners and separate health/connection budgets. Do not send different database protocols to this PostgreSQL listener.
