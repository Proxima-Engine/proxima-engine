#!/usr/bin/env bash
set -euo pipefail

container="proxima-cassandra-ci-$RANDOM"
tenant_a_password="$(openssl rand -hex 24)"
tenant_b_password="$(openssl rand -hex 24)"
cleanup() { docker rm -f "$container" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Start an unauthenticated bootstrap instance; authentication is enabled after first startup.
echo "Starting disposable Cassandra 5 container"
docker run -d --name "$container" -p 127.0.0.1:19042:9042 cassandra:5.0 >/dev/null

# Let the image finish its first boot before editing its effective config.
# Otherwise the entrypoint can race this change and start with AllowAll auth.
initial_ready=0
for _ in $(seq 1 120); do
  if docker exec "$container" cqlsh -e "SELECT release_version FROM system.local" >/dev/null 2>&1; then
    initial_ready=1
    break
  fi
  sleep 5
done
if [[ "$initial_ready" != 1 ]]; then
  docker logs "$container"
  echo "Cassandra did not complete its initial startup" >&2
  exit 1
fi
echo "Cassandra initial startup is ready"

docker exec -u 0 "$container" bash -ec 'set -eux
  config=/etc/cassandra/cassandra.yaml
  temporary_config="$(mktemp)"
  awk "
    /^authenticator:[[:space:]]*[^[:space:]]/ {
      sub(/:.*/, \": PasswordAuthenticator\")
      section=\"\"
      print
      next
    }
    /^authorizer:[[:space:]]*[^[:space:]]/ {
      sub(/:.*/, \": CassandraAuthorizer\")
      section=\"\"
      print
      next
    }
    /^role_manager:[[:space:]]*[^[:space:]]/ {
      sub(/:.*/, \": CassandraRoleManager\")
      section=\"\"
      print
      next
    }
    /^authenticator:[[:space:]]*$/ { section=\"authenticator\"; print; next }
    /^authorizer:[[:space:]]*$/ { section=\"authorizer\"; print; next }
    /^role_manager:[[:space:]]*$/ { section=\"role_manager\"; print; next }
    /^[^[:space:]]/ { section=\"\" }
    section == \"authenticator\" && /^[[:space:]]*class_name:/ {
      sub(/class_name:.*/, \"class_name: PasswordAuthenticator\")
    }
    section == \"authorizer\" && /^[[:space:]]*class_name:/ {
      sub(/class_name:.*/, \"class_name: CassandraAuthorizer\")
    }
    section == \"role_manager\" && /^[[:space:]]*class_name:/ {
      sub(/class_name:.*/, \"class_name: CassandraRoleManager\")
    }
    { print }
  " "$config" > "$temporary_config"
  cat "$temporary_config" > "$config"
  rm -f "$temporary_config"
  grep -A4 -E "^authenticator:" "$config" | grep -q "PasswordAuthenticator"
  grep -A4 -E "^authorizer:" "$config" | grep -q "CassandraAuthorizer"
  grep -A4 -E "^role_manager:" "$config" | grep -q "CassandraRoleManager"
  grep -n -A4 -E "^(authenticator|authorizer|role_manager):" "$config"
'
echo "Cassandra authentication configuration updated"
docker restart "$container" >/dev/null
echo "Cassandra restarted with authentication enabled"

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
