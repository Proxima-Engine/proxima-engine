# Proxima database gateways on Kubernetes

This chart packages the Engine's protocol gateways and optional desired-state controller. Gateway workloads run as non-root Deployments behind internal ClusterIP Services. Database protocols are not exposed publicly by this chart.

## Supported gateway runtimes

The assignment controller reconciles these gateway runtimes:

- MySQL
- MongoDB
- Redis
- Microsoft SQL Server (TDS 7.4)

Other supported database providers use their native Engine runtime and are not converted into Kubernetes gateway workloads by this chart.

## Prerequisites

- Kubernetes 1.27+ with a CNI that enforces NetworkPolicy.
- A Proxima Engine image containing the gateway and controller binaries.
- A shared PVC used by the Engine node and controller.
- Provider-specific TLS material and identity data delivered through the protected Engine secret manifest.
- A client workload labelled proxima.io/client=true.

## Assignment controller

The controller reads two Engine-owned files from the shared volume:

- database-targets.json — authenticated desired assignments, provider runtime, target, node and delivery revisions.
- database-target-secrets.json — the matching versioned credential and gateway-file manifest.

The controller validates the schema, node identity, delivery ID, assignment IDs and configuration revisions before applying resources. It reconciles a Deployment, ClusterIP Service, Kubernetes Secret and NetworkPolicy for each active supported gateway assignment. It uses server-side apply and ownership labels, and removes only stale resources managed by this controller for the same Engine node.

After reconciliation it writes gateway-runtime-status.json atomically. The Engine uses this observed state in its runtime lifecycle. A failed reconciliation retains the last successfully applied workloads and reports the error; it does not silently remove a working gateway.

The controller reconciles Kubernetes Secret contents when the Engine delivers a new credential manifest. Upstream database-user creation or revocation remains provider-specific and belongs to the credential lifecycle/provisioning workflow; Kubernetes Secret deletion alone does not revoke an account inside a database.

## Shared volume

Mount the same PVC into the Engine node and controller. The Engine writes desired state and credential manifests; the controller reads them and writes runtime status. The controller needs read/write access to the volume. Use a ReadWriteMany-capable claim when the pods can run on different nodes.

The secret manifest contains sensitive material. Keep the PVC private to the Engine and controller service accounts, use restrictive filesystem permissions, encrypt storage where supported, and never commit the manifest or its contents.

The chart refuses to enable the controller without an existing claim. Example values:

    controller:
      enabled: true
      configVolume:
        existingClaim: proxima-engine-state
        mountPath: /var/lib/proxima
      reconcileSeconds: 15
      gatewayImage:
        repository: ghcr.io/proxima-engine/proxima-engine
        tag: <release-tag>

Enable the controller only when the Engine node writes both manifests to that same claim. Do not enable static gateways.*.enabled Deployments at the same time; the chart enforces this to prevent duplicate workloads.

## Install

Create the shared PVC and configure the Engine node to write its desired-state files there. Then install the chart with the controller enabled and the provider-specific network policy values reviewed:

    helm upgrade --install proxima-gateways ./deploy/kubernetes/helm/proxima-gateways \
      --namespace proxima-system --create-namespace \
      --set controller.enabled=true \
      --set controller.configVolume.existingClaim=proxima-engine-state

Set allowed egress CIDRs and ports for the database targets. Keep networkPolicy.enabled true. The chart keeps gateway Services internal and restricts workload egress to the reviewed policy.

## Security and RBAC

The controller uses a namespace-scoped ServiceAccount and Role. Its permissions are limited to Deployments, Services, Secrets and NetworkPolicies in the release namespace; it does not need cluster-admin or cluster-wide resource access. The controller runs as non-root, with a read-only root filesystem, dropped Linux capabilities and a restricted security context.

The static gateway mode and assignment-controller mode are mutually exclusive. Use the controller mode for Cloud/Engine desired-state reconciliation.

## Operational acceptance

A Ready Pod or open TCP port proves only that the workload is running and listening. It does not prove upstream connectivity or tenant isolation. Run the provider-specific connectivity and negative isolation checks, then confirm the Engine's observed runtime status and signed verification evidence before treating an assignment as applied.
