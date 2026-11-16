use serde_json::{json, Value};
use std::{env, error::Error, fs, path::Path};

struct TableFinding {
    schema: String, table: String, owner: String,
    rls_enabled: bool, rls_forced: bool, owner_bypasses_rls: bool,
    public_select: bool, policy_count: i64,
}
fn ident(v: &str) -> String { format!("\"{}\"", v.replace('"', "\"\"")) }
fn literal(v: &str) -> String { format!("'{}'", v.replace('\'', "''")) }

async fn inspect(url: &str) -> Result<Vec<TableFinding>, Box<dyn Error>> {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls).await?;
    tokio::spawn(async move { if let Err(e) = connection.await { eprintln!("audit connection ended: {e}"); } });
    let rows = client.query(r#"
        SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner),
               c.relrowsecurity, c.relforcerowsecurity,
               COALESCE(r.rolsuper OR r.rolbypassrls, false),
               EXISTS (SELECT 1 FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
                       WHERE a.grantee = 0 AND a.privilege_type = 'SELECT'),
               (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        LEFT JOIN pg_roles r ON r.rolname = pg_get_userbyid(c.relowner)
        WHERE c.relkind IN ('r','p')
          AND n.nspname NOT IN ('pg_catalog','information_schema')
          AND n.nspname NOT LIKE 'pg_toast%'
        ORDER BY n.nspname,c.relname
    "#, &[]).await?;
    Ok(rows.into_iter().map(|r| TableFinding {
        schema:r.get(0), table:r.get(1), owner:r.get(2), rls_enabled:r.get(3),
        rls_forced:r.get(4), owner_bypasses_rls:r.get(5), public_select:r.get(6),
        policy_count:r.get(7)
    }).collect())
}
fn report(rows: &[TableFinding]) -> Value {
    let tables: Vec<Value> = rows.iter().map(|f| {
        let mut issues: Vec<&str> = Vec::new();
        if !f.rls_enabled { issues.push("rls_disabled"); }
        if f.rls_enabled && !f.rls_forced { issues.push("rls_not_forced"); }
        if !f.rls_forced || f.owner_bypasses_rls { issues.push("table_owner_bypasses_rls"); }
        if f.public_select { issues.push("public_select_grant"); }
        if f.rls_enabled && f.policy_count == 0 { issues.push("no_rls_policies"); }
        json!({"schema":f.schema,"table":f.table,"owner":f.owner,
          "rls_enabled":f.rls_enabled,"rls_forced":f.rls_forced,
          "owner_bypasses_rls":f.owner_bypasses_rls,"public_select":f.public_select,
          "policy_count":f.policy_count,"findings":issues})
    }).collect();
    let count: usize = tables.iter().map(|t| t["findings"].as_array().map_or(0, Vec::len)).sum();
    json!({"schema":"agata-proxima.postgresql-posture.v1",
      "scope":"non-system ordinary and partitioned tables visible to the audit role",
      "table_count":tables.len(),"finding_count":count,
      "status":if count==0 {"no_catalog_findings"} else {"attention_required"},
      "limitations":[
        "Catalog inspection cannot prove an arbitrary policy implements the intended tenant boundary.",
        "Views, functions, dynamic SQL, role membership and application authorization require separate review.",
        "A clean report is not a security certification."
      ],"tables":tables})
}
fn generate(spec: &Value) -> Result<String, Box<dyn Error>> {
    let tables=spec.get("tables").and_then(Value::as_array).ok_or("policy spec requires tables array")?;
    if tables.is_empty() { return Err("tables array cannot be empty".into()); }
    let mut out=String::from("-- Agata Proxima generated SQL. Review and apply through migrations.\n-- Tenant identity is bound to current_user, not a client-writable GUC.\n");
    for t in tables {
        let schema=t["schema"].as_str().ok_or("schema required")?;
        let name=t["table"].as_str().ok_or("table required")?;
        let column=t["tenant_column"].as_str().ok_or("tenant_column required")?;
        let policy=t["policy_name"].as_str().unwrap_or("proxima_tenant_isolation");
        let tenants=t["tenants"].as_array().ok_or("tenants array required")?;
        if tenants.is_empty() { return Err(format!("{schema}.{name}: tenants cannot be empty").into()); }
        let mut predicates=Vec::new(); let mut roles=Vec::new();
        for tenant in tenants {
            let id=tenant["tenant_id"].as_str().ok_or("tenant_id required")?;
            let role=tenant["role"].as_str().ok_or("role required")?;
            predicates.push(format!("({} = {} AND current_user = {})",ident(column),literal(id),literal(role)));
            roles.push(ident(role));
        }
        let target=format!("{}.{}",ident(schema),ident(name));
        let predicate=predicates.join(" OR ");
        out.push_str(&format!("\nALTER TABLE {target} ENABLE ROW LEVEL SECURITY;\nALTER TABLE {target} FORCE ROW LEVEL SECURITY;\nDROP POLICY IF EXISTS {} ON {target};\nCREATE POLICY {} ON {target} FOR ALL TO {} USING ({predicate}) WITH CHECK ({predicate});\n",ident(policy),ident(policy),roles.join(", ")));
    }
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
   assert!(!sql.contains("current_setting"));
 }
 #[test] fn flags_non_forced_owner_bypass() {
   let rows=vec![TableFinding{schema:"public".into(),table:"orders".into(),owner:"app_owner".into(),rls_enabled:true,rls_forced:false,owner_bypasses_rls:false,public_select:false,policy_count:1}];
   let value=report(&rows);
   assert!(value["tables"][0]["findings"].as_array().unwrap().iter().any(|v|v=="table_owner_bypasses_rls"));
 }
 #[test] fn rejects_empty_mapping() {
   let spec=json!({"tables":[{"schema":"public","table":"orders","tenant_column":"tenant_id","tenants":[]}]});
   assert!(generate(&spec).is_err());
 }
}
