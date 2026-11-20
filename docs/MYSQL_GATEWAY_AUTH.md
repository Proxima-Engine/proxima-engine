# MySQL gateway client authentication

The gateway supports both `mysql_native_password` (legacy compatibility) and
`caching_sha2_password` (preferred for new clients). New client principals
should use the SHA-256 verifier format below.

## Registry verifier formats

A principal must contain exactly one verifier:

- `password_sha256`: lowercase or uppercase hexadecimal encoding of
  `SHA256(SHA256(password))`; selects `caching_sha2_password`.
- `password_sha1`: hexadecimal encoding of `SHA1(password)`; selects
  `mysql_native_password` for legacy compatibility.

Do not store plaintext passwords in the registry. The gateway compares the
client's 32-byte caching-SHA-2 challenge response against the stored
double-SHA-256 verifier using constant-time comparison. It then sends the
protocol's fast-auth success packet followed by the normal OK packet. It does
not ask clients to send plaintext passwords and does not implement an RSA
password fallback. The client-facing gateway listener remains loopback-only;
do not expose it on an untrusted network.

Example shape (replace all illustrative values before use):

```json
{
  "users": [{
    "username": "application_user",
    "tenant_id": "tenant-a",
    "database": "tenant_a",
    "upstream_url": "mysql://tenant_a_gateway:REPLACE_ME@127.0.0.1:3306/tenant_a",
    "auth_plugin": "caching_sha2_password",
    "password_sha256": "64_HEX_CHARACTERS_FROM_SHA256_SHA256"
  }]
}
```

The upstream database credential is separate from the client-facing password
verifier. Continue to provision a distinct least-privilege upstream account
for every tenant. The upstream URL database must match the registry database.

Legacy entries using `password_sha1` remain supported. Migrate them by
computing the SHA-256 verifier from the original application password and
replacing the verifier; the original password cannot be recovered from the
SHA-1 verifier.
