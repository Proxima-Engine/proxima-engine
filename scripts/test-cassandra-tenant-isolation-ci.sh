#!/usr/bin/env bash
set -euo pipefail

container="proxima-cassandra-ci-$RANDOM"
tenant_a_password="$(openssl rand -hex 24)"
tenant_b_password="$(openssl rand -hex 24)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# The official Cassandra image does not consistently apply auth settings from
# environment variables across major versions. Set the authoritative YAML
# configuration explicitly before running the acceptance checks.
docker run -d --name "$container" -p 127.0.0.1:19042:9042 cassandra:5.0 >/dev/null
docker exec "$container" bash -ec '
  config=/etc/cassandra/cassandra.yaml
  sed -i -E \
    -e "s/^([[:space:]]*authenticator:).*/\\1 PasswordAuthenticator/" \
    -e "s/^([[:space:]]*authorizer:).*/\\1 CassandraAuthorizer/" \
    -e "s/^([[:space:]]*role_manager:).*/\\1 CassandraRoleManager/" \
    "$config"
  grep -Eq "^authenticator:[[:space:]]*PasswordAuthenticator$" "$config"
  grep -Eq "^authorizer:[[:space:]]*CassandraAuthorizer$" "$config"
  grep -Eq "^role_manager:[[:space:]]*CassandraRoleManager$" "$config"
'
docker restart "$container" >/dev/null

ready=0
for _ in $(seq 1 120); do
  if docker exec "$container" cqlsh -u cassandra -p cassandra -e "SELECT release_version FROM system.local" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 5
done
if [[ "$ready" != 1 ]]; then
  docker logs "$container"
  echo "Cassandra did not become ready with PasswordAuthenticator and CassandraAuthorizer enabled" >&2
  exit 1
fi

docker exec -i "$container" cqlsh -u cassandra -p cassandra <<CQL
CREATE KEYSPACE proxima_tenant_a WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':1};
CREATE KEYSPACE proxima_tenant_b WITH replication = {'class':'NetworkTopologyStrategy','datacenter1':1};
CREATE TABLE proxima_tenant_a.records (id text PRIMARY KEY, payload text);
CREATE TABLE proxima_tenant_b.records (id text PRIMARY KEY, payload text);
CREATE ROLE proxima_tenant_a_app WITH PASSWORD = '$tenant_a_password' AND LOGIN = true;
CREATE ROLE proxima_tenant_b_app WITH PASSWORD = '$tenant_b_password' AND LOGIN = true;
GRANT SELECT ON KEYSPACE proxima_tenant_a TO proxima_tenant_a_app;
GRANT MODIFY ON KEYSPACE proxima_tenant_a TO proxima_tenant_a_app;
GRANT SELECT ON KEYSPACE proxima_tenant_b TO proxima_tenant_b_app;
GRANT MODIFY ON KEYSPACE proxima_tenant_b TO proxima_tenant_b_app;
CQL

docker exec "$container" cqlsh -u proxima_tenant_a_app -p "$tenant_a_password" -e "INSERT INTO proxima_tenant_a.records (id,payload) VALUES ('a','tenant-a-only');"
docker exec "$container" cqlsh -u proxima_tenant_b_app -p "$tenant_b_password" -e "INSERT INTO proxima_tenant_b.records (id,payload) VALUES ('b','tenant-b-only');"

a_output="$(docker exec "$container" cqlsh -u proxima_tenant_a_app -p "$tenant_a_password" -e "SELECT payload FROM proxima_tenant_a.records WHERE id='a'")"
b_output="$(docker exec "$container" cqlsh -u proxima_tenant_b_app -p "$tenant_b_password" -e "SELECT payload FROM proxima_tenant_b.records WHERE id='b'")"
grep -q 'tenant-a-only' <<<"$a_output"
grep -q 'tenant-b-only' <<<"$b_output"

expect_denied() {
  local user="$1" password="$2" statement="$3"
  if docker exec "$container" cqlsh -u "$user" -p "$password" -e "$statement" > /tmp/proxima-cassandra-denial.log 2>&1; then
    echo "Cassandra tenant isolation failure: $user unexpectedly executed $statement" >&2
    cat /tmp/proxima-cassandra-denial.log >&2
    exit 1
  fi
}
expect_denied proxima_tenant_a_app "$tenant_a_password" "SELECT payload FROM proxima_tenant_b.records WHERE id='b'"
expect_denied proxima_tenant_b_app "$tenant_b_password" "SELECT payload FROM proxima_tenant_a.records WHERE id='a'"
expect_denied proxima_tenant_a_app "$tenant_a_password" "CREATE TABLE proxima_tenant_a.forbidden (id text PRIMARY KEY)"

echo "Cassandra keyspace-per-tenant isolation: PASS"
