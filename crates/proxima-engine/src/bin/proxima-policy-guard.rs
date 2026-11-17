use serde_json::{json, Value};
use std::{collections::HashSet, env, error::Error, fs, io::BufReader, path::Path, str::FromStr, time::Duration};
use tokio_postgres::config::SslMode;
use tokio_postgres_rustls::MakeRustlsConnect;

struct TableFinding {
    schema: String, table: String, owner: String,
    rls_enabled: bool, rls_forced: bool, owner_bypasses_rls: bool,
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
    client.batch_execute("SET default_transaction_read_only = on; SET statement_timeout = '10s'; SET lock_timeout = '2s';").await?;
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
                 WHERE owner_member.rolsuper OR owner_member.rolbypassrls
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
        rls_forced:r.get(4), owner_bypasses_rls:r.get(5), public_select:r.get(6),
        public_write_or_truncate:r.get(7), truncate_grant:r.get(8), bypass_role_grant:r.get(9),
        policy_count:r.get(10), permissive_policy_count:r.get(11), security_definer_routines:r.get(12)
    }).collect())
}
fn report(rows: &[TableFinding]) -> Value {
    let tables: Vec<Value> = rows.iter().map(|f| {
        let mut issues: Vec<&str> = Vec::new();
        if !f.rls_enabled { issues.push("rls_disabled"); }
        if f.rls_enabled && !f.rls_forced { issues.push("rls_not_forced"); }
        if !f.rls_forced || f.owner_bypasses_rls { issues.push("table_owner_bypasses_rls"); }
        if f.public_select { issues.push("public_select_grant"); }
        if f.public_write_or_truncate { issues.push("public_write_or_truncate_grant"); }
        if f.truncate_grant { issues.push("non_owner_truncate_grant"); }
        if f.bypass_role_grant { issues.push("bypassrls_or_superuser_role_has_table_grant"); }
        if f.rls_enabled && f.policy_count == 0 { issues.push("no_rls_policies"); }
        if f.permissive_policy_count > 1 { issues.push("multiple_permissive_policies_require_review"); }
        if f.security_definer_routines > 0 { issues.push("security_definer_routines_require_review"); }
        json!({"schema":f.schema,"table":f.table,"owner":f.owner,
          "rls_enabled":f.rls_enabled,"rls_forced":f.rls_forced,
          "owner_bypasses_rls":f.owner_bypasses_rls,"public_select":f.public_select,
          "public_write_or_truncate":f.public_write_or_truncate,"truncate_grant":f.truncate_grant,"bypass_role_grant":f.bypass_role_grant,
          "policy_count":f.policy_count,"permissive_policy_count":f.permissive_policy_count,
          "security_definer_routines":f.security_definer_routines,"findings":issues})
    }).collect();
    let count: usize = tables.iter().map(|t| t["findings"].as_array().map_or(0, Vec::len)).sum();
    json!({"schema":"agata-proxima.postgresql-posture.v1",
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
    let mut out=String::from("-- Agata Proxima generated SQL. Review and apply through migrations.\n-- Tenant identity is bound to current_user, not a client-writable GUC.\nBEGIN;\n");
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
            if id.is_empty()||id.len()>256||id.contains('\0')||!valid_role_name(role)
                || !tenant_ids.insert(id)||!role_names.insert(role) {
                return Err(format!("{schema}.{name}: invalid or duplicate tenant-to-role mapping").into());
            }
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
               AND a.attnum>0 AND NOT a.attisdropped
               AND format_type(a.atttypid,a.atttypmod) NOT IN ('text','uuid','integer','bigint','smallint','numeric','citext')
               AND format_type(a.atttypid,a.atttypmod) NOT LIKE 'character varying%'
               AND format_type(a.atttypid,a.atttypmod) NOT LIKE 'character(%')
     THEN RAISE EXCEPTION 'Agata Proxima: tenant key type is unsupported'; END IF;
  IF owner_name = ANY({role_array}) THEN RAISE EXCEPTION 'Agata Proxima: tenant runtime roles must not own the protected table'; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=ANY({role_array}) AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
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
                    OR lower(setting) LIKE 'session_replication_role=replica%'))
     THEN RAISE EXCEPTION 'Agata Proxima: tenant role/database defaults can change security state'; END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname=owner_name AND (rolsuper OR rolbypassrls))
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
    out.push_str("\nCOMMIT;\n");
    Ok(out)
}
#[tokio::main]
async fn main() -> Result<(),Box<dyn Error>> {
    let mut args=env::args().skip(1);
    match args.next().as_deref() {
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
      _ => return Err("usage: proxima-policy-guard <audit|generate>".into())
    }
    Ok(())
}
#[cfg(test)]
mod tests {
 use super::*;
 #[test] fn escapes_sql_names_and_values() {
   assert_eq!(ident("a\"b"),"\"a\"\"b\"");
   assert_eq!(literal("a'b"),"'a''b'");
 }
 #[test] fn generator_uses_role_bound_identity() {
   let spec=json!({"tables":[{"schema":"public","table":"orders","tenant_column":"tenant_id","tenants":[
     {"tenant_id":"tenant-a","role":"proxima_tenant_a"},{"tenant_id":"tenant-b","role":"proxima_tenant_b"}]}]});
   let sql=generate(&spec).unwrap();
   assert!(sql.contains("current_user = 'proxima_tenant_a'"));
   assert!(sql.contains("\"tenant_id\" = 'tenant-b'"));
   assert!(sql.contains("FORCE ROW LEVEL SECURITY"));
   assert!(sql.contains("other permissive RLS policies must be reconciled first"));
   assert!(sql.contains("BEGIN;"));
   assert!(sql.contains("COMMIT;"));
   assert!(!sql.contains("current_setting"));
   assert!(!sql.contains("DROP POLICY"));
   assert!(sql.contains("policy name already exists"));
 }
 #[test] fn flags_non_forced_owner_bypass() {
   let rows=vec![TableFinding{schema:"public".into(),table:"orders".into(),owner:"app_owner".into(),rls_enabled:true,rls_forced:false,owner_bypasses_rls:false,public_select:false,public_write_or_truncate:false,truncate_grant:false,bypass_role_grant:false,policy_count:1,permissive_policy_count:1,security_definer_routines:0}];
   let value=report(&rows);
   assert!(value["tables"][0]["findings"].as_array().unwrap().iter().any(|v|v=="table_owner_bypasses_rls"));
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
