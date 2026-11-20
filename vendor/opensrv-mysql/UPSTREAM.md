# Vendored OpenSrv MySQL protocol layer

This directory is based on the MySQL server crate from
[databendlabs/opensrv](https://github.com/databendlabs/opensrv), tag
`v0.7.0` (Apache-2.0).

The local delta is intentionally narrow: the handshake path emits the
MySQL `caching_sha2_password` fast-auth success packet (`0x01 0x03`)
after the Proxima identity verifier accepts the challenge response. The
auth-switch path also restarts authentication when the selected per-user
plugin differs from the initial handshake plugin, even when the first
plugin already supplied a response.

Keep upstream changes isolated and review them against the original release.
