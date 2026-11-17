use serde_json::{json, Value};
use proxima_engine::security_core::{adapter_catalog, AccessDecision, TenantSecurityPolicy, SECURITY_MODEL_VERSION};
use proxima_engine::database_adapter::{AdapterError, AdapterFuture, AdapterTarget, DatabaseAdapter, DiscoveryRequest, InspectionRequest};
use proxima_engine::postgres_adapter::{PostgresCatalogAdapter, PostgresConnector};
use proxima_engine::native_policy_plans::{compile_mongodb_database_boundary, compile_mysql_database_boundary, compile_redis_acl, compile_sql_server};
use std::{collections::HashSet, env, error::Error, fs, io::BufReader, path::Path, str::FromStr, time::Duration};
use tokio_postgres::config::SslMode;
use tokio_postgres_rustls::MakeRustlsConnect;

struct TableFinding {
    schema: String, table: String, owner: String,
    rls_enabled: bool, rls_forced: bool, owner_has_elevated_privileges: bool,
    public_select: bool, public_write_or_truncate: bool, truncate_grant: bool, bypass_role_grant: bool,
    policy_count: i64, permissive_policy_count: i64, security_definer_routines: i64,
}
fn ident(v: &str) -> String { format!("\"{}\"", v.replace('"', "\"\"")) }
fn literal(v: &str) -> String { format!("'{}'", v.replace('\'', "''")) }
fn validate_ident(v: &str, label: &str) -> Result<(), Box<dyn Error>> {
    if v.is_empty() || v.as_bytes().len() > 63 || v.contains('\0') {
        return Err(format!("{label} must contain 1–63 UTF-8 bytes and no NUL byte").into());
    }
    Ok(())
}
fn valid_role_name(v: &str) -> bool {
    if v.is_empty() || v.len()>63 { return false; }
    let mut chars=v.chars();
    matches!(chars.next(),Some(c) if c.is_ascii_alphabetic()||c=='_')
        && chars.all(|c|c.is_ascii_alphanumeric()||c=='_')
}

fn audit_tls_connector() -> Result<MakeRustlsConnect, Box<dyn Error>> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Ok(path) = env::var("PROXIMA_POLICY_AUDIT_TLS_CA_FILE") {
        let file = fs::File::open(path)?;
        let mut reader = BufReader::new(file);
        let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
        if certificates.is_empty() { return Err("custom TLS CA file contains no certificates".into()); }
        for certificate in certificates { roots.add(certificate)?; }
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

async fn inspect(url: &str) -> Result<Vec<TableFinding>, Box<dyn Error>> {
    let mut config = tokio_postgres::Config::from_str(url)?;
    config.ssl_mode(SslMode::Require);
    let tls = audit_tls_connector()?;
    let (client, connection) = tokio::time::timeout(Duration::from_secs(10), config.connect(tls)).await??;
    tokio::spawn(async move { if let Err(e) = connection.await { eprintln!("audit connection ended: {e}"); } });
    client.batch_execute("SET default_transaction_read_only = on; SET statement_timeout = '10s'; SET lock_timeout = '2s'; SET search_path = pg_catalog, pg_temp;").await?;
    let unsafe_inspector: bool = client.query_one(r#"
      WITH RECURSIVE member_roles(role_oid) AS (
        SELECT oid FROM pg_roles WHERE rolname=current_user
        UNION
        SELECT am.roleid FROM pg_auth_members am JOIN member_roles mr ON am.member=mr.role_oid
      )
      SELECT EXISTS(SELECT 1 FROM member_roles mr JOIN pg_roles r ON r.oid=mr.role_oid WHERE r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)
        OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE c.relkind IN ('r','p','v','m') AND n.nspname NOT IN ('pg_catalog','information_schema')
            AND (has_table_privilege(current_user,c.oid,'INSERT')
              OR has_table_privilege(current_user,c.oid,'UPDATE')
              OR has_table_privilege(current_user,c.oid,'DELETE')
              OR has_table_privilege(current_user,c.oid,'TRUNCATE')))
        OR has_database_privilege(current_user,current_database(),'CREATE')
        OR EXISTS(SELECT 1 FROM pg_namespace n
          WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_%'
            AND has_schema_privilege(current_user,n.oid,'CREATE'))
    "#, &[]).await?.get(0);
    if unsafe_inspector { return Err("audit login must be read-only and must not be SUPERUSER or BYPASSRLS".into()); }
    let rows = client.query(r#"
        SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner),
               c.relrowsecurity, c.relforcerowsecurity,
               (COALESCE(r.rolsuper OR r.rolbypassrls,false) OR EXISTS(
                 WITH RECURSIVE owner_roles(role_oid) AS (
                   SELECT c.relowner UNION SELECT am.roleid FROM pg_auth_members am JOIN owner_roles o ON am.member=o.role_oid
                 )
                 SELECT 1 FROM owner_roles o JOIN pg_roles owner_member ON owner_member.oid=o.role_oid
                 WHERE owner_member.rolsuper OR owner_member.rolbypassrls OR owner_member.rolcreaterole OR owner_member.rolcreatedb OR owner_member.rolreplication
               )),
               EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
                       WHERE a.grantee = 0 AND a.privilege_type = 'SELECT'),
               EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
                       WHERE a.grantee = 0 AND a.privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE')),
               (EXISTS (SELECT 1 FROM pg_roles grantee WHERE grantee.rolname<>pg_get_userbyid(c.relowner) AND has_table_privilege(grantee.rolname,c.oid,'TRUNCATE')) OR EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl WHERE acl.grantee=0 AND acl.privilege_type='TRUNCATE')),
               EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
                       WHERE a.grantee<>0 AND EXISTS(
                         WITH RECURSIVE granted_roles(role_oid) AS (
                           SELECT a.grantee UNION SELECT am.roleid FROM pg_auth_members am JOIN granted_roles g ON am.member=g.role_oid
                         )
                         SELECT 1 FROM granted_roles g JOIN pg_roles gr ON gr.oid=g.role_oid WHERE gr.rolsuper OR gr.rolbypassrls
                       )),
               (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid),
               (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid AND p.polpermissive),
               (SELECT count(*) FROM pg_proc routine JOIN pg_namespace routine_schema ON routine_schema.oid=routine.pronamespace
                 WHERE routine.prosecdef AND routine.prokind IN ('f','p')
                   AND routine_schema.nspname NOT IN ('pg_catalog','information_schema')
                   AND routine_schema.nspname NOT LIKE 'pg_%')
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_roles r ON r.rolname = pg_get_userbyid(c.relowner)
        WHERE c.relkind IN ('r','p')
          AND n.nspname NOT IN ('pg_catalog','information_schema')
          AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp_%'
        ORDER BY n.nspname,c.relname
    "#, &[]).await?;
    Ok(rows.into_iter().map(|r| TableFinding {
        schema:r.get(0), table:r.get(1), owner:r.get(2), rls_enabled:r.get(3),
        rls_forced:r.get(4), owner_has_elevated_privileges:r.get(5), public_select:r.get(6),
        public_write_or_truncate:r.get(7), truncate_grant:r.get(8), bypass_role_grant:r.get(9),
        policy_count:r.get(10), permissive_policy_count:r.get(11), security_definer_routines:r.get(12)
    }).collect())
}
fn report(rows: &[TableFinding]) -> Value {
    let tables: Vec<Value> = rows.iter().map(|f| {
        let mut issues: Vec<&str> = Vec::new();
        if !f.rls_enabled { issues.push("rls_disabled"); }
        if f.rls_enabled && !f.rls_forced { issues.push("rls_not_forced"); }
        if !f.rls_forced || f.owner_has_elevated_privileges { issues.push("table_owner_has_elevated_privileges"); }
        if f.public_select { issues.push("public_select_grant"); }
        if f.public_write_or_truncate { issues.push("public_write_or_truncate_grant"); }
        if f.truncate_grant { issues.push("non_owner_truncate_grant"); }
        if f.bypass_role_grant { issues.push("bypassrls_or_superuser_role_has_table_grant"); }
        if f.rls_enabled && f.policy_count == 0 { issues.push("no_rls_policies"); }
        if f.permissive_policy_count > 1 { issues.push("multiple_permissive_policies_require_review"); }
        if f.security_definer_routines > 0 { issues.push("security_definer_routines_require_review"); }
        json!({"schema":f.schema,"table":f.table,"owner":f.owner,
          "rls_enabled":f.rls_enabled,"rls_forced":f.rls_forced,
          "owner_has_elevated_privileges":f.owner_has_elevated_privileges,"public_select":f.public_select,
          "public_write_or_truncate":f.public_write_or_truncate,"truncate_grant":f.truncate_grant,"bypass_role_grant":f.bypass_role_grant,
          "policy_count":f.policy_count,"permissive_policy_count":f.permissive_policy_count,
          "security_definer_routines":f.security_definer_routines,"findings":issues})
    }).collect();
    let count: usize = tables.iter().map(|t| t["findings"].as_array().map_or(0, Vec::len)).sum();
    json!({"schema":"agata-proxima.postgresql-posture.v1",
      "security_model_version":SECURITY_MODEL_VERSION,
      "database_kind":"postgresql",
      "adapter_maturity":"in_development",
      "inspection_status":"inspection_only",
      "security_posture":"unknown",
      "access_decision":"deny",
      "scope":"non-system ordinary and partitioned tables visible to the audit role",
      "table_count":tables.len(),"finding_count":count,
      "status":if count==0 {"no_catalog_findings"} else {"attention_required"},
      "limitations":[
        "Catalog inspection cannot prove an arbitrary policy implements the intended tenant boundary.",
        "Views, functions, dynamic SQL and application authorization require separate review.",
        "A clean report is not a security certification."
      ],"tables":tables})
}
fn generate(spec: &Value) -> Result<String, Box<dyn Error>> {
    let tables=spec.get("tables").and_then(Value::as_array).ok_or("policy spec requires tables array")?;
    if tables.is_empty() { return Err("tables array cannot be empty".into()); }
    if tables.len()>100 { return Err("at most 100 tables may be generated in one policy spec".into()); }
    let mut seen_tables=HashSet::new();
    let mut required_role_prefix:Option<String>=None;
    let mut out=String::from("-- Agata Proxima generated SQL. Review and apply through migrations.\n-- Tenant identity is bound to current_user, not a client-writable GUC.\n-- All role mappings must use one Engine prefix plus the normalized verified tenant ID.\nBEGIN;\nSET LOCAL search_path = pg_catalog, pg_temp;\n");
    for t in tables {
        let schema=t["schema"].as_str().ok_or("schema required")?;
        let name=t["table"].as_str().ok_or("table required")?;
        let column=t["tenant_column"].as_str().ok_or("tenant_column required")?;
        let policy=t["policy_name"].as_str().unwrap_or("proxima_tenant_isolation");
        for (value,label) in [(schema,"schema"),(name,"table"),(column,"tenant column"),(policy,"policy name")] {
            validate_ident(value,label)?;
        }
        if schema=="pg_catalog" || schema=="information_schema" || schema.starts_with("pg_toast") || schema.starts_with("pg_temp") {
            return Err(format!("{schema}.{name}: system and temporary schemas cannot be managed").into());
        }
        if !seen_tables.insert((schema.to_owned(),name.to_owned())) {
            return Err(format!("{schema}.{name}: duplicate table mapping in policy spec").into());
        }
        let tenants=t["tenants"].as_array().ok_or("tenants array required")?;
        if tenants.is_empty() || tenants.len()>100 { return Err(format!("{schema}.{name}: tenant mappings must contain 1-100 entries").into()); }
        let mut predicates=Vec::new(); let mut roles=Vec::new();
        let mut tenant_ids=std::collections::HashSet::new();
        let mut role_names=std::collections::HashSet::new();
        for tenant in tenants {
            let id=tenant["tenant_id"].as_str().ok_or("tenant_id required")?;
            let role=tenant["role"].as_str().ok_or("role required")?;
            if id.is_empty()||id.len()>128||!id.bytes().all(|byte|byte.is_ascii_alphanumeric()||byte==b'-'||byte==b'_')||!valid_role_name(role)
                || !tenant_ids.insert(id)||!role_names.insert(role) {
                return Err(format!("{schema}.{name}: invalid or duplicate tenant-to-role mapping").into());
            }
            let normalized_id=id.replace('-', "_");
            if !role.ends_with(&normalized_id) {
                return Err(format!("{schema}.{name}: role {role} does not match the Engine prefix-plus-tenant-ID contract").into());
            }
            let prefix_length=role.len().saturating_sub(normalized_id.len());
            let role_prefix=&role[..prefix_length];
            if role_prefix.is_empty()||!role_prefix.bytes().all(|byte|byte.is_ascii_alphanumeric()||byte==b'_') {
                return Err(format!("{schema}.{name}: role {role} has an invalid Engine prefix").into());
            }
            if required_role_prefix.as_deref().is_some_and(|expected|expected!=role_prefix) {
                return Err(format!("{schema}.{name}: all tenant roles must use one shared PROXIMA_TENANT_ROLE_PREFIX").into());
            }
            required_role_prefix=Some(role_prefix.to_owned());
            predicates.push(format!("({} = {} AND current_user = {})",ident(column),literal(id),literal(role)));
            roles.push(ident(role));
        }
        let target=format!("{}.{}",ident(schema),ident(name));
        let predicate=predicates.join(" OR ");
        let role_values=tenants.iter().map(|tenant|literal(tenant["role"].as_str().unwrap())).collect::<Vec<_>>().join(", ");
        let role_array=format!("ARRAY[{role_values}]::name[]");
        let preflight=format!(r#"
DO $agata_proxima_preflight$
DECLARE owner_name name;
BEGIN
  SELECT pg_get_userbyid(c.relowner) INTO owner_name
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname={schema_literal} AND c.relname={table_literal} AND c.relkind IN ('r','p');
  IF owner_name IS NULL THEN RAISE EXCEPTION 'Agata Proxima: target table does not exist'; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
                 WHERE n.nspname={schema_literal} AND c.relname={table_literal} AND a.attname={column_literal}
                   AND a.attnum>0 AND NOT a.attisdropped)
     THEN RAISE EXCEPTION 'Agata Proxima: tenant key column does not exist'; END IF;
  IF EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname={schema_literal} AND c.relname={table_literal} AND a.attname={column_literal}
               AND a.attnum>0 AND NOT a.attisdropped AND NOT a.attnotnull)
     THEN RAISE EXCEPTION 'Agata Proxima: tenant key column must be NOT NULL'; END IF;
  IF EXISTS (SELECT 1 FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname={schema_literal} AND c.relname={table_literal} AND a.attname={column_literal}
               AND a.attnum>0 AND NOT a.attisdropped
               AND format_type(a.atttypid,a.atttypmod) NOT IN ('text','uuid','integer','bigint','smallint','numeric','citext')
               AND format_type(a.atttypid,a.atttypmod) NOT LIKE 'character varying%'
               AND format_type(a.atttypid,a.atttypmod) NOT LIKE 'character(%')
     THEN RAISE EXCEPTION 'Agata Proxima: tenant key type is unsupported'; END IF;
  IF owner_name = ANY({role_array}) THEN RAISE EXCEPTION 'Agata Proxima: tenant runtime roles must not own the protected table'; END IF;
  IF EXISTS (SELECT 1 FROM pg_inherits partition_edge
             WHERE partition_edge.inhrelid=(SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname={schema_literal} AND c.relname={table_literal})
                OR partition_edge.inhparent=(SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname={schema_literal} AND c.relname={table_literal}))
     THEN RAISE EXCEPTION 'Agata Proxima: partitioned relations require native child-partition verification before policy generation'; END IF;
  IF EXISTS (
       WITH RECURSIVE dependent_views(view_oid) AS (
         SELECT rewrite.ev_class FROM pg_depend dependency
         JOIN pg_rewrite rewrite ON dependency.classid='pg_rewrite'::regclass AND dependency.objid=rewrite.oid
         WHERE dependency.refclassid='pg_class'::regclass
           AND dependency.refobjid=(SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname={schema_literal} AND c.relname={table_literal})
         UNION
         SELECT rewrite.ev_class FROM pg_depend dependency
         JOIN pg_rewrite rewrite ON dependency.classid='pg_rewrite'::regclass AND dependency.objid=rewrite.oid
         JOIN dependent_views parent_view ON dependency.refobjid=parent_view.view_oid
         WHERE dependency.refclassid='pg_class'::regclass
       )
       SELECT 1 FROM dependent_views dependency
       JOIN pg_class view_relation ON view_relation.oid=dependency.view_oid
       JOIN pg_namespace view_namespace ON view_namespace.oid=view_relation.relnamespace
       WHERE view_relation.relkind IN ('v','m')
         AND view_namespace.nspname NOT IN ('pg_catalog','information_schema')
         AND (view_relation.relkind='m' OR NOT COALESCE(view_relation.reloptions @> ARRAY['security_invoker=true'],false))
     )
     THEN RAISE EXCEPTION 'Agata Proxima: dependent views must use security_invoker=true and materialized views require separate protection'; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles tenant_role WHERE tenant_role.rolname=ANY({role_array})
             AND (has_database_privilege(tenant_role.rolname,current_database(),'CREATE')
               OR EXISTS(SELECT 1 FROM pg_namespace ns
                 WHERE ns.nspname NOT IN ('pg_catalog','information_schema') AND ns.nspname NOT LIKE 'pg_%'
                   AND has_schema_privilege(tenant_role.rolname,ns.oid,'CREATE'))))
     THEN RAISE EXCEPTION 'Agata Proxima: tenant runtime roles must not have database or schema CREATE privileges'; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=ANY({role_array}) AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR NOT rolcanlogin))
     OR (WITH RECURSIVE member_roles(role_oid) AS (
          SELECT oid FROM pg_roles WHERE rolname=ANY({role_array})
          UNION SELECT am.roleid FROM pg_auth_members am JOIN member_roles mr ON am.member=mr.role_oid
        ) SELECT EXISTS(SELECT 1 FROM member_roles mr JOIN pg_roles r ON r.oid=mr.role_oid WHERE r.rolsuper OR r.rolbypassrls))
     OR EXISTS (SELECT 1 FROM pg_auth_members am JOIN pg_roles r ON r.oid=am.roleid OR r.oid=am.member WHERE r.rolname=ANY({role_array}))
     THEN RAISE EXCEPTION 'Agata Proxima: tenant roles must exist, have no role memberships, and must not bypass RLS'; END IF;
  IF (SELECT count(*) FROM pg_roles WHERE rolname=ANY({role_array})) <> {role_count}
     THEN RAISE EXCEPTION 'Agata Proxima: one or more tenant roles do not exist'; END IF;
  IF EXISTS (SELECT 1 FROM pg_db_role_setting s LEFT JOIN pg_roles r ON r.oid=s.setrole
             WHERE (s.setrole=0 OR r.rolname=ANY({role_array}))
               AND (s.setdatabase=0 OR s.setdatabase=(SELECT oid FROM pg_database WHERE datname=current_database()))
               AND EXISTS(SELECT 1 FROM unnest(s.setconfig) setting
                 WHERE lower(setting) LIKE 'role=%'
                    OR lower(setting) LIKE 'session_authorization=%'
                    OR lower(setting) LIKE 'row_security=off%'
                    OR lower(setting) LIKE 'row_security=false%'
                    OR lower(setting) LIKE 'row_security=0%'
                    OR lower(setting) LIKE 'row_security=no%'
                    OR lower(setting) LIKE 'search_path=%'
                    OR lower(setting) LIKE 'session_replication_role=replica%'))
     THEN RAISE EXCEPTION 'Agata Proxima: tenant role/database defaults can change security state'; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=owner_name AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
     THEN RAISE EXCEPTION 'Agata Proxima: table owner bypasses row security'; END IF;
  IF EXISTS (WITH RECURSIVE owner_roles(role_oid) AS (
               SELECT oid FROM pg_roles WHERE rolname=owner_name
               UNION SELECT am.roleid FROM pg_auth_members am JOIN owner_roles o ON am.member=o.role_oid
             ) SELECT 1 FROM owner_roles o JOIN pg_roles r ON r.oid=o.role_oid WHERE r.rolsuper OR r.rolbypassrls)
     THEN RAISE EXCEPTION 'Agata Proxima: table owner membership bypasses row security'; END IF;
  IF EXISTS (SELECT 1 FROM pg_policies WHERE schemaname={schema_literal} AND tablename={table_literal}
             AND permissive='PERMISSIVE' AND policyname<>{policy_literal})
     THEN RAISE EXCEPTION 'Agata Proxima: other permissive RLS policies must be reconciled first'; END IF;
  IF EXISTS (SELECT 1 FROM pg_proc routine JOIN pg_namespace routine_schema ON routine_schema.oid=routine.pronamespace
             WHERE routine.prosecdef AND routine.prokind IN ('f','p')
               AND routine_schema.nspname NOT IN ('pg_catalog','information_schema')
               AND routine_schema.nspname NOT LIKE 'pg_%')
     THEN RAISE EXCEPTION 'Agata Proxima: SECURITY DEFINER routines require separate review before claiming tenant isolation'; END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname={schema_literal} AND c.relname={table_literal}
               AND EXISTS (SELECT 1 FROM pg_roles grantee
                           WHERE grantee.rolname<>owner_name AND has_table_privilege(grantee.rolname,c.oid,'TRUNCATE')))
     THEN RAISE EXCEPTION 'Agata Proxima: non-owner TRUNCATE grants bypass RLS'; END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname={schema_literal} AND c.relname={table_literal}
               AND EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl
                           WHERE acl.grantee=0 AND acl.privilege_type IN ('SELECT','INSERT','UPDATE','DELETE','TRUNCATE')))
     THEN RAISE EXCEPTION 'Agata Proxima: PUBLIC has table privileges; reconcile PUBLIC grants before policy generation'; END IF;
  IF EXISTS (SELECT 1 FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid
             JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname={schema_literal} AND c.relname={table_literal} AND p.polname={policy_literal})
     THEN RAISE EXCEPTION 'Agata Proxima: policy name already exists; review the existing policy before replacement'; END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
             WHERE n.nspname={schema_literal} AND c.relname={table_literal}
               AND EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) acl
                 WHERE acl.grantee<>0 AND acl.grantee<>c.relowner AND EXISTS(
                   WITH RECURSIVE granted_roles(role_oid) AS (
                     SELECT acl.grantee UNION SELECT am.roleid FROM pg_auth_members am JOIN granted_roles g ON am.member=g.role_oid
                   )
                   SELECT 1 FROM granted_roles g JOIN pg_roles r ON r.oid=g.role_oid WHERE r.rolsuper OR r.rolbypassrls
                 )))
     THEN RAISE EXCEPTION 'Agata Proxima: a table grantee can bypass row security'; END IF;
END;
$agata_proxima_preflight$;
"#,schema_literal=literal(schema),table_literal=literal(name),column_literal=literal(column),policy_literal=literal(policy),role_array=role_array,role_count=tenants.len());
        out.push_str(&preflight);
        out.push_str(&format!("\nALTER TABLE {target} ENABLE ROW LEVEL SECURITY;\nALTER TABLE {target} FORCE ROW LEVEL SECURITY;\nCREATE POLICY {} ON {target} FOR ALL TO {} USING ({predicate}) WITH CHECK ({predicate});\n",ident(policy),roles.join(", ")));
    }
    let prefix=required_role_prefix.ok_or("policy spec did not define an Engine role prefix")?;
    out.push_str(&format!("\n-- Required PROXIMA_TENANT_ROLE_PREFIX: {prefix}\n"));
    out.push_str("\nCOMMIT;\n");
    Ok(out)
}
#[tokio::main]
async fn main() -> Result<(),Box<dyn Error>> {
    let mut args=env::args().skip(1);
    match args.next().as_deref() {
      Some("validate-policy") => {
        let path=args.next().ok_or("usage: proxima-policy-guard validate-policy <policy.json>")?;
        let source=fs::read_to_string(&path)?;
        let policy:TenantSecurityPolicy=serde_json::from_str(&source)?;
        match policy.validate() {
          Ok(()) => println!("{}",serde_json::to_string_pretty(&json!({
            "valid":true,
            "schema_version":policy.schema_version,
            "policy_id":policy.policy_id,
            "revision":policy.revision,
            "resource_count":policy.resources.len()
          }))?),
          Err(error) => {
            println!("{}",serde_json::to_string_pretty(&json!({"valid":false,"error":format!("{error:?}")}))?);
            std::process::exit(2);
          }
        }
      },
      Some("compile-plan") => {
        let database = args.next().ok_or("usage: proxima-policy-guard compile-plan <postgresql|sql_server|mysql|mariadb|mongodb|redis> <policy.json>")?;
        let path = args.next().ok_or("usage: proxima-policy-guard compile-plan <postgresql|sql_server|mysql|mariadb|mongodb|redis> <policy.json>")?;
        let source = fs::read_to_string(&path)?;
        let policy: TenantSecurityPolicy = serde_json::from_str(&source)?;
        let compiled = match database.as_str() {
          "postgresql" => {
            let connector: PostgresConnector = std::sync::Arc::new(|| Box::pin(async {
              Err(AdapterError { code: "compile_only_connector".into(), detail: "PostgreSQL plan compilation does not connect to a database.".into(), retryable: false })
            }));
            let tenant_role_prefix = env::var("PROXIMA_TENANT_ROLE_PREFIX")
              .map_err(|_| "set PROXIMA_TENANT_ROLE_PREFIX to compile a role-bound PostgreSQL policy")?;
            let adapter = PostgresCatalogAdapter::new("compile-only", "compile-only", tenant_role_prefix, connector)?;
            adapter.compile_policy(&policy)?
          },
          "sql_server" => compile_sql_server(&policy)?,
          "mysql" => compile_mysql_database_boundary(&policy, proxima_engine::security_core::DatabaseKind::MySql)?,
          "mariadb" => compile_mysql_database_boundary(&policy, proxima_engine::security_core::DatabaseKind::MariaDb)?,
          "mongodb" => compile_mongodb_database_boundary(&policy)?,
          "redis" => compile_redis_acl(&policy)?,
          _ => return Err("unsupported compile-plan database; choose postgresql, sql_server, mysql, mariadb, mongodb, or redis".into())
        };
        println!("{}", serde_json::to_string_pretty(&compiled)?);
        eprintln!("Review-only policy plan generated. No database connection or DDL/ACL change was made.");
      },
      Some("adapters") => {
        let value=json!({"schema_version":SECURITY_MODEL_VERSION,"scope":"engine_runtime","adapter_contract":"database_adapter::DatabaseAdapter","adapters":adapter_catalog()});
        println!("{}",serde_json::to_string_pretty(&value)?);
      },
      Some("discover-postgres") => {
        let namespace = args.next();
        if args.next().is_some() { return Err("usage: proxima-policy-guard discover-postgres [schema]".into()); }
        let url = env::var("PROXIMA_POSTGRES_ADAPTER_DATABASE_URL")
            .map_err(|_| "set PROXIMA_POSTGRES_ADAPTER_DATABASE_URL to a TLS-verified PostgreSQL URL")?;
        let target_id = env::var("PROXIMA_POSTGRES_ADAPTER_TARGET_ID")
            .map_err(|_| "set PROXIMA_POSTGRES_ADAPTER_TARGET_ID to the registered non-secret target ID")?;
        let database_name = env::var("PROXIMA_POSTGRES_ADAPTER_DATABASE_NAME")
            .map_err(|_| "set PROXIMA_POSTGRES_ADAPTER_DATABASE_NAME to the expected database name")?;
        let tenant_role_prefix = env::var("PROXIMA_TENANT_ROLE_PREFIX")
            .map_err(|_| "set PROXIMA_TENANT_ROLE_PREFIX to the Engine's tenant role prefix")?;
        let connector_url = url.clone();
        let connector: PostgresConnector = std::sync::Arc::new(move || {
            let connector_url = connector_url.clone();
            Box::pin(async move {
                let mut config = tokio_postgres::Config::from_str(&connector_url)
                    .map_err(|error| AdapterError { code: "invalid_postgres_connection_config".into(), detail: error.to_string(), retryable: false })?;
                config.ssl_mode(SslMode::Require);
                let tls = audit_tls_connector()
                    .map_err(|error| AdapterError { code: "postgres_tls_configuration_failed".into(), detail: error.to_string(), retryable: false })?;
                let (client, connection) = tokio::time::timeout(Duration::from_secs(10), config.connect(tls))
                    .await
                    .map_err(|error| AdapterError { code: "postgres_connection_timeout".into(), detail: error.to_string(), retryable: true })?
                    .map_err(|error| AdapterError { code: "postgres_connection_failed".into(), detail: error.to_string(), retryable: error.is_closed() })?;
                tokio::spawn(async move {
                    if let Err(error) = connection.await {
                        eprintln!("PostgreSQL discovery connection ended: {error}");
                    }
                });
                Ok(client)
            }) as AdapterFuture<'static, Result<tokio_postgres::Client, AdapterError>>
        });
        let adapter = PostgresCatalogAdapter::new(target_id.clone(), database_name.clone(), tenant_role_prefix, connector)?;
        let snapshot = adapter.discover(&DiscoveryRequest {
            target: AdapterTarget { target_id, database_name, namespace: None },
            namespace,
        }).await?;
        println!("{}", serde_json::to_string_pretty(&json!({
            "adapter": adapter.descriptor(),
            "discovery": snapshot,
            "access_decision": "deny",
            "note": "Discovery inventories native resources. It does not certify tenant isolation or authorize traffic."
        }))?);
      },
      Some("inspect-policy") => {
        let path = args.next().ok_or("usage: proxima-policy-guard inspect-policy <policy.json>")?;
        let policy: TenantSecurityPolicy = serde_json::from_slice(&fs::read(&path)?)?;
        policy.validate().map_err(|error| format!("invalid policy: {error:?}"))?;
        let url = env::var("PROXIMA_POSTGRES_ADAPTER_DATABASE_URL")
            .map_err(|_| "set PROXIMA_POSTGRES_ADAPTER_DATABASE_URL to a TLS-verified PostgreSQL URL")?;
        let target_id = env::var("PROXIMA_POSTGRES_ADAPTER_TARGET_ID")
            .map_err(|_| "set PROXIMA_POSTGRES_ADAPTER_TARGET_ID to the registered non-secret target ID")?;
        let database_name = env::var("PROXIMA_POSTGRES_ADAPTER_DATABASE_NAME")
            .map_err(|_| "set PROXIMA_POSTGRES_ADAPTER_DATABASE_NAME to the expected database name")?;
        let tenant_role_prefix = env::var("PROXIMA_TENANT_ROLE_PREFIX")
            .map_err(|_| "set PROXIMA_TENANT_ROLE_PREFIX to the Engine's tenant role prefix")?;
        let connector_url = url.clone();
        let connector: PostgresConnector = std::sync::Arc::new(move || {
            let connector_url = connector_url.clone();
            Box::pin(async move {
                let mut config = tokio_postgres::Config::from_str(&connector_url)
                    .map_err(|error| AdapterError { code: "invalid_postgres_connection_config".into(), detail: error.to_string(), retryable: false })?;
                config.ssl_mode(SslMode::Require);
                let tls = audit_tls_connector()
                    .map_err(|error| AdapterError { code: "postgres_tls_configuration_failed".into(), detail: error.to_string(), retryable: false })?;
                let (client, connection) = tokio::time::timeout(Duration::from_secs(10), config.connect(tls))
                    .await
                    .map_err(|error| AdapterError { code: "postgres_connection_timeout".into(), detail: error.to_string(), retryable: true })?
                    .map_err(|error| AdapterError { code: "postgres_connection_failed".into(), detail: error.to_string(), retryable: error.is_closed() })?;
                tokio::spawn(async move {
                    if let Err(error) = connection.await {
                        eprintln!("PostgreSQL adapter connection ended: {error}");
                    }
                });
                Ok(client)
            }) as AdapterFuture<'static, Result<tokio_postgres::Client, AdapterError>>
        });
        let adapter = PostgresCatalogAdapter::new(target_id.clone(), database_name.clone(), tenant_role_prefix, connector)?;
        let request = InspectionRequest {
            target: AdapterTarget {
                target_id,
                database_name,
                namespace: None,
            },
            policy,
        };
        let snapshot = adapter.inspect(&request).await?;
        let verification = adapter.verify(&request.policy, &snapshot).await?;
        let decision = verification.access_decision();
        println!("{}", serde_json::to_string_pretty(&json!({
            "adapter": adapter.descriptor(),
            "snapshot": snapshot,
            "verification": verification,
            "access_decision": decision
        }))?);
        if decision != AccessDecision::Allow { std::process::exit(2); }
      },
      Some("audit") => {
        let url=env::var("PROXIMA_POLICY_AUDIT_DATABASE_URL").map_err(|_|"set PROXIMA_POLICY_AUDIT_DATABASE_URL to a read-only inspection URL")?;
        let value=report(&inspect(&url).await?);
        println!("{}",serde_json::to_string_pretty(&value)?);
        if value["finding_count"].as_u64().unwrap_or(0)>0 { std::process::exit(2); }
      },
      Some("generate") => {
        let path=args.next().ok_or("usage: proxima-policy-guard generate <policy-spec.json>")?;
        let spec:Value=serde_json::from_slice(&fs::read(Path::new(&path))?)?;
        print!("{}",generate(&spec)?);
      },
      _ => return Err("usage: proxima-policy-guard <adapters|audit|generate|validate-policy|compile-plan|discover-postgres|inspect-policy>".into())
    }
    Ok(())
}
#[cfg(test)]
mod tests {
 use super::*;
 #[test] fn catalog_audit_never_claims_verified_posture() {
   let value=report(&[]);
   assert_eq!(value["security_posture"],"unknown");
   assert_eq!(value["access_decision"],"deny");
   assert_eq!(value["inspection_status"],"inspection_only");
 }
 #[test] fn escapes_sql_names_and_values() {
   assert_eq!(ident("a\"b"),"\"a\"\"b\"");
   assert_eq!(literal("a'b"),"'a''b'");
 }
 #[test] fn generator_uses_role_bound_identity() {
   let spec=json!({"tables":[{"schema":"public","table":"orders","tenant_column":"tenant_id","tenants":[
     {"tenant_id":"tenant-a","role":"proxima_tenant_tenant_a"},{"tenant_id":"tenant-b","role":"proxima_tenant_tenant_b"}]}]});
   let sql=generate(&spec).unwrap();
   assert!(sql.contains("current_user = 'proxima_tenant_tenant_a'"));
   assert!(sql.contains("\"tenant_id\" = 'tenant-b'"));
   assert!(sql.contains("FORCE ROW LEVEL SECURITY"));
   assert!(sql.contains("other permissive RLS policies must be reconciled first"));
   assert!(sql.contains("BEGIN;"));
   assert!(sql.contains("COMMIT;"));
   assert!(sql.contains("Required PROXIMA_TENANT_ROLE_PREFIX: proxima_tenant_"));
   assert!(!sql.contains("current_setting"));
   assert!(!sql.contains("DROP POLICY"));
   assert!(sql.contains("policy name already exists"));
 }
 #[test] fn flags_non_forced_rls_and_owner_privileges() {
   let rows=vec![TableFinding{schema:"public".into(),table:"orders".into(),owner:"app_owner".into(),rls_enabled:true,rls_forced:false,owner_has_elevated_privileges:false,public_select:false,public_write_or_truncate:false,truncate_grant:false,bypass_role_grant:false,policy_count:1,permissive_policy_count:1,security_definer_routines:0}];
   let value=report(&rows);
   assert!(value["tables"][0]["findings"].as_array().unwrap().iter().any(|v|v=="table_owner_has_elevated_privileges"));
 }
 #[test] fn rejects_empty_mapping() {
   let spec=json!({"tables":[{"schema":"public","table":"orders","tenant_column":"tenant_id","tenants":[]}]});
   assert!(generate(&spec).is_err());
 }
 #[test] fn rejects_overlong_postgres_identifiers() {
   let spec=json!({"tables":[{"schema":"public","table":"x".repeat(64),"tenant_column":"tenant_id","tenants":[{"tenant_id":"a","role":"proxima_a"}]}]});
   assert!(generate(&spec).is_err());
 }
 #[test] fn rejects_duplicate_tenant_roles() {
   let spec=json!({"tables":[{"schema":"public","table":"orders","tenant_column":"tenant_id","tenants":[
     {"tenant_id":"tenant-a","role":"proxima_shared"},{"tenant_id":"tenant-b","role":"proxima_shared"}]}]});
   assert!(generate(&spec).is_err());
 }
 #[test] fn rejects_duplicate_table_mappings() {
   let spec=json!({"tables":[
     {"schema":"public","table":"orders","tenant_column":"tenant_id","tenants":[{"tenant_id":"a","role":"proxima_a"}]},
     {"schema":"public","table":"orders","tenant_column":"tenant_id","tenants":[{"tenant_id":"b","role":"proxima_b"}]}
   ]});
   assert!(generate(&spec).is_err());
 }
 #[test] fn rejects_nul_and_unsafe_role_identifiers() {
   let nul_identifier=json!({"tables":[{"schema":format!("public{}", '\0'),"table":"orders","tenant_column":"tenant_id","tenants":[{"tenant_id":"a","role":"proxima_a"}]}]});
   let nul_tenant=json!({"tables":[{"schema":"public","table":"orders","tenant_column":"tenant_id","tenants":[{"tenant_id":format!("a{}b", '\0'),"role":"proxima_a"}]}]});
   let invalid_role=json!({"tables":[{"schema":"public","table":"orders","tenant_column":"tenant_id","tenants":[{"tenant_id":"a","role":"proxima-a"}]}]});
   assert!(generate(&nul_identifier).is_err());
   assert!(generate(&nul_tenant).is_err());
   assert!(generate(&invalid_role).is_err());
 }
}
