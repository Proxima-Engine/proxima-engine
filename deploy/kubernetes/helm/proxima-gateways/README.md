# Proxima database gateways on Kubernetes

This chart deploys each existing protocol gateway as an independent, non-root
Deployment behind a ClusterIP Service. It does not expose database protocols
publicly and does not claim to provision upstream database users.

## Prerequisites

- Kubernetes 1.27+ with a CNI that enforces NetworkPolicy.
- The published Proxima Engine image containing all three gateway binaries.
- A Kubernetes Secret for every enabled gateway. Secrets are mounted read-only;
  never commit registry JSON, passwords, certificates, or private keys.
- A client workload labelled `proxima.io/client=true`.

## Secret contracts

Create each secret in the release namespace before enabling its gateway:

- MySQL: key `users.json`, containing the MySQL identity registry schema.
- MongoDB: keys `users.json`, `tls.crt`, `tls.key`, `ca.crt`.
- Redis: keys `users.json`, `tls.crt`, `tls.key`, `ca.crt`.

The registry files must conform to the respective Engine gateway registry
schemas. MongoDB and Redis upstream TLS are enabled by default. MySQL upstream
TLS requirements are validated by its registry loader.

## Install

Create secrets with your secret manager or external-secrets controller, then:

```sh
helm upgrade --install proxima-gateways ./deploy/kubernetes/helm/proxima-gateways \
  --namespace proxima-system --create-namespace \
  --set gateways.mysql.enabled=true \
  --set gateways.mongodb.enabled=true \
  --set gateways.redis.enabled=true
```

Set each enabled gateway's upstream addresses, TLS server names, and allowed
egress CIDRs/ports in a reviewed values file. Keep `networkPolicy.enabled`
true. NetworkPolicy egress to upstream databases is denied unless explicitly
listed in `networkPolicy.egressCIDRs`; DNS is allowed.

Services are internal ClusterIP endpoints:
- `proxima-gateways-mysql:3307`
- `proxima-gateways-mongodb:27018`
- `proxima-gateways-redis:6380`

## Operational boundary

TCP probes verify that the listener is accepting connections; they do not prove
upstream connectivity or tenant isolation. The Cloud/Engine signed
configuration acknowledgement must remain staged until provider-specific
connectivity and isolation evidence is produced. This chart is workload
packaging, not a Kubernetes operator: it does not yet reconcile Cloud
assignments, rotate registry Secrets, or automatically revoke provider users.
Use a secret controller to roll pods on secret rotation. Do not treat a Ready
Pod as a Cloud-level applied assignment.
