#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
redis_id="proxima-redis-ci-$RANDOM"
gateway_pid=""
cleanup(){ [[ -n "$gateway_pid" ]] && kill "$gateway_pid" 2>/dev/null || true; docker rm -f "$redis_id" >/dev/null 2>&1 || true; rm -rf "$tmp"; }
trap cleanup EXIT
mkdir -p "$tmp/tls"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$tmp/tls/ca.key" -out "$tmp/tls/ca.crt" -subj "/CN=Proxima Redis CI CA" -days 1 >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$tmp/tls/server.key" -out "$tmp/tls/server.csr" -subj "/CN=localhost" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$tmp/tls/ext.cnf"
openssl x509 -req -in "$tmp/tls/server.csr" -CA "$tmp/tls/ca.crt" -CAkey "$tmp/tls/ca.key" -CAcreateserial -out "$tmp/tls/server.crt" -days 1 -extfile "$tmp/tls/ext.cnf" >/dev/null 2>&1
cp "$tmp/tls/server.crt" "$tmp/tls/gateway.crt"; cp "$tmp/tls/server.key" "$tmp/tls/gateway.key"
openssl req -newkey rsa:2048 -nodes -keyout "$tmp/tls/gateway.key" -out "$tmp/tls/gateway.csr" -subj "/CN=localhost" >/dev/null 2>&1
openssl x509 -req -in "$tmp/tls/gateway.csr" -CA "$tmp/tls/ca.crt" -CAkey "$tmp/tls/ca.key" -CAcreateserial -out "$tmp/tls/gateway.crt" -days 1 -extfile "$tmp/tls/ext.cnf" >/dev/null 2>&1
docker run -d --name "$redis_id" -p 127.0.0.1:6389:6379 -v "$tmp/tls:/tls:ro" redis:7.4-alpine redis-server --port 0 --tls-port 6379 --tls-cert-file /tls/server.crt --tls-key-file /tls/server.key --tls-ca-cert-file /tls/ca.crt --tls-auth-clients no --user 'default on >proxima-admin-ci ~* &* +@all' >/dev/null
for _ in $(seq 1 40); do redis-cli --tls --cacert "$tmp/tls/ca.crt" -h 127.0.0.1 -p 6389 PING >/dev/null 2>&1 && break; sleep 1; done
redis-cli --tls --cacert "$tmp/tls/ca.crt" -h 127.0.0.1 -p 6389 ACL SETUSER tenant_a on '>upstream-a' '~proxima:{ca978112ca1bbdcafac231b39a23dc4d}:*' +get +set +del +exists +mget +mset +incr +expire +ttl +type +bitop >/dev/null
redis-cli --tls --cacert "$tmp/tls/ca.crt" -h 127.0.0.1 -p 6389 ACL SETUSER tenant_b on '>upstream-b' '~proxima:{3e23e8160039594a33894f6564e1b134}:*' +get +set +del +exists +mget +mset +incr +expire +ttl +type +bitop >/dev/null
hash_a="$(printf client-a | sha256sum | cut -d' ' -f1)"
hash_b="$(printf client-b | sha256sum | cut -d' ' -f1)"
cat > "$tmp/identities.json" <<JSON
{"users":[{"username":"client_a","tenant_id":"a","client_password_sha256":"$hash_a","upstream_username":"tenant_a","upstream_password":"upstream-a"},{"username":"client_b","tenant_id":"b","client_password_sha256":"$hash_b","upstream_username":"tenant_b","upstream_password":"upstream-b"}]}
JSON
export PROXIMA_REDIS_LISTEN_ADDR=127.0.0.1:6380
export PROXIMA_REDIS_UPSTREAM_ADDR=127.0.0.1:6389
export PROXIMA_REDIS_UPSTREAM_TLS_SERVER_NAME=localhost
export PROXIMA_REDIS_UPSTREAM_TLS_CA_FILE="$tmp/tls/ca.crt"
export PROXIMA_REDIS_TLS_CERT_FILE="$tmp/tls/gateway.crt"
export PROXIMA_REDIS_TLS_KEY_FILE="$tmp/tls/gateway.key"
export PROXIMA_REDIS_IDENTITY_REGISTRY="$tmp/identities.json"
"$root/target/debug/proxima-redis-gateway" > "$tmp/gateway.log" 2>&1 & gateway_pid=$!
for _ in $(seq 1 40); do redis-cli --tls --insecure -h 127.0.0.1 -p 6380 --user client_a -a client-a PING 2>/dev/null | grep -q PONG && break; sleep 1; done
client(){ local user="$1" pass="$2"; shift 2; redis-cli --raw --tls --insecure -h 127.0.0.1 -p 6380 --user "$user" -a "$pass" "$@"; }
[[ "$(client client_a client-a SET shared alpha)" == "OK" ]]
[[ "$(client client_b client-b SET shared beta)" == "OK" ]]
[[ "$(client client_a client-a GET shared)" == "alpha" ]]
[[ "$(client client_b client-b GET shared)" == "beta" ]]
[[ "$(client client_a client-a MGET shared)" == "alpha" ]]
[[ "$(client client_a client-a BITOP AND combined shared shared)" == "1" ]]
if client client_a client-a FLUSHALL >/dev/null 2>&1; then echo "FLUSHALL unexpectedly succeeded" >&2; exit 1; fi
if client client_a wrong-password GET shared >/dev/null 2>&1; then echo "invalid gateway credentials unexpectedly succeeded" >&2; exit 1; fi
echo "Redis TLS gateway two-tenant acceptance: PASS"
