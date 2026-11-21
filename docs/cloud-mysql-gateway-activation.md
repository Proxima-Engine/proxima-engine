# Cloud-assigned MySQL gateway activation

The node configuration worker now has a supervised activation path for MySQL/MariaDB assignments. It does not infer tenant credentials from target-level credentials.

## Encrypted credential payload

The Control Plane stores this object inside the encrypted database target secret. The node receives it only inside the node-bound AES-256-GCM envelope:

```json
{
  "username": "control-plane-target-user",
  "password": "<target-secret>",
  "authentication_database": null,
  "gateway_runtime_config": {
    "schema_version": 1,
    "provider_key": "mysql",
    "listen_addr": "127.0.0.1:3307",
    "users": [
      {
        "username": "tenant-a-client",
        "tenant_id": "<tenant-a-uuid>",
        "database": "tenant_a",
        "upstream_url": "mysql://tenant_a_upstream:<secret>@db.example.com:3306/tenant_a?require_ssl=true",
        "password_sha1": "<40-hex-character-mysql-native-password-verifier>",
        "auth_plugin": "mysql_native_password"
      }
    ]
  }
}
```

The users array must map exactly to the assignment's tenant_bindings by tenant_id. The existing MySQL identity-registry parser validates verifier format, database mapping, duplicate usernames, and verified TLS requirements before the child process starts. Do not place plaintext client passwords in the registry; supply the verifier supported by the existing gateway.

## Activation sequence

1. Verify the signed node bundle and decrypt the AES-256-GCM envelope with the existing node-bound AAD.
2. Persist the staged assignment and desired/applied revision record.
3. If Cloud reports cloud_integration_state=preview, acknowledge staged only. The Cloud preview gate is not bypassed.
4. If Cloud reports enabled, validate the provider-specific identity registry against every tenant binding.
5. Write the registry under the node state directory with owner-only permissions on Unix.
6. Start proxima-mysql-gateway under RuntimeProcessSupervisor and wait for its loopback listener.
7. Authenticate to the upstream MySQL endpoint using the first configured tenant upstream URL and issue a ping.
8. Only after startup and upstream authentication succeed, persist Applied and send the signed applied acknowledgement. On failure, stop the child and send a signed failed acknowledgement.

## Current scope

This branch connects MySQL/MariaDB to the coordinator. MongoDB and Redis are deliberately fail-closed in this activation path until their provider-specific registry generation and authenticated upstream probes are connected. PostgreSQL/CockroachDB continue to use the native Engine runtime and are not launched as a gateway child by this change. Runtime process recovery across Engine restarts and provider-specific tenant provisioning/isolation evidence remain separate work; a successful target-level acknowledgement does not activate tenant bindings.
