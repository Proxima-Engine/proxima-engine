use sqlparser::{dialect::PostgreSqlDialect, parser::Parser};

/// Conservatively rejects statements that can change the effective PostgreSQL
/// identity, weaken row security, bypass RLS operations, or alter the policy
/// boundary for a tenant-bound session. PostgreSQL remains the syntax authority.
pub fn blocks_tenant_session_mutation(sql: &str) -> bool {
    let dialect = PostgreSqlDialect {};
    if Parser::parse_sql(&dialect, sql).is_err() {
        // Never forward tenant-bound SQL that the PostgreSQL dialect parser cannot validate.
        return true;
    }
    let Ok(tokens) = sqlparser::tokenizer::Tokenizer::new(&dialect, sql).tokenize() else {
        // A tenant-bound session must not forward SQL the guard cannot tokenize.
        return true;
    };
    let tokens: Vec<String> = tokens.iter()
        .filter(|token| !matches!(token, sqlparser::tokenizer::Token::Whitespace(_)))
        .map(|token| token.to_string().to_ascii_lowercase().replace('"', ""))
        .collect();
    let at = |index: usize, expected: &str| tokens.get(index).is_some_and(|value| value == expected);

    if tokens.iter().any(|token| token.trim_matches('"').ends_with("set_config")) {
        return true;
    }

    for index in 0..tokens.len() {
        let statement_start = index == 0 || at(index - 1, ";");
        if !statement_start { continue; }

        if at(index,"do") || at(index,"call") || at(index,"truncate")
            || at(index,"grant") || at(index,"revoke")
            || at(index,"discard") && at(index+1,"all")
            || at(index,"comment") && at(index+1,"on")
            || at(index,"refresh") && at(index+1,"materialized") && at(index+2,"view")
            || at(index,"reset") && (at(index+1,"all") || at(index+1,"role")
                || at(index+1,"row_security") || at(index+1,"search_path") || at(index+1,"schema")
                || at(index+1,"session") && at(index+2,"authorization")) {
            return true;
        }

        if at(index,"set") {
            let mut cursor=index+1;
            if at(cursor,"session") && at(cursor+1,"authorization") { return true; }
            if at(cursor,"session") || at(cursor,"local") { cursor+=1; }
            if at(cursor,"session") && at(cursor+1,"authorization") { return true; }
            if at(cursor,"role") || at(cursor,"session_authorization")
                || at(cursor,"row_security") || at(cursor,"session_replication_role")
                || at(cursor,"search_path") || at(cursor,"schema") {
                return true;
            }
        }

        // Tenant-bound sessions are not database-administration sessions. Reject
        // DDL wholesale so CREATE/ALTER/DROP variants cannot introduce views,
        // routines, rules, triggers, schemas, extensions, or new privilege paths.
        if at(index,"create") || at(index,"alter") || at(index,"drop") {
            return true;
        }
    }
    false
}

/// Reject client startup options that could set a different role, disable RLS,
/// change replication semantics, or redirect object resolution before SQL is inspected.
pub fn blocks_tenant_startup_options(options: &str) -> bool {
    let compact: String = options.chars()
        .filter(|character| !character.is_whitespace() && *character!='\'' && *character!='"')
        .collect::<String>().to_ascii_lowercase();
    if compact.contains("role=") || compact.contains("session_authorization=")
        || compact.contains("row_security=") || compact.contains("session_replication_role=")
        || compact.contains("search_path=") {
        return true;
    }
    let tokens: Vec<&str> = options.split_whitespace().collect();
    let mut index=0;
    while index<tokens.len() {
        let token=tokens[index].trim_matches(|character|character=='\''||character=='"');
        if token=="-c" || token=="--set" {
            if let Some(next)=tokens.get(index+1) {
                let assignment=next.trim_matches(|character|character=='\''||character=='"').to_ascii_lowercase();
                if ["role","session_authorization","row_security","session_replication_role"]
                    .iter().any(|key|assignment.starts_with(&format!("{key}="))) { return true; }
            }
        }
        index+=1;
    }
    false
}

/// Extracts SQL text from one complete PostgreSQL simple-query (Q) or Parse (P) frame.
pub fn sql_from_frontend_frame(frame: &[u8]) -> Option<&str> {
    if frame.len()<5 { return None; }
    let length=i32::from_be_bytes(frame[1..5].try_into().ok()?);
    if length<4 || frame.len()!=length as usize+1 { return None; }
    let payload=&frame[5..];
    match frame[0] {
        b'Q' => {
            let (sql,trailing)=split_c_string(payload)?;
            if trailing.is_empty(){Some(sql)}else{None}
        }
        b'P' => {
            let (_,remainder)=split_c_string(payload)?;
            let (sql,_parameters)=split_c_string(remainder)?;
            Some(sql)
        }
        _=>None,
    }
}

fn split_c_string(bytes:&[u8])->Option<(&str,&[u8])>{
    let end=bytes.iter().position(|byte|*byte==0)?;
    Some((std::str::from_utf8(&bytes[..end]).ok()?,&bytes[end+1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_role_security_and_policy_mutations() {
        for sql in [
            "SET ROLE proxima_tenant_other",
            "SET \"role\" TO proxima_tenant_other",
            "SET LOCAL ROLE proxima_tenant_other",
            "RESET ROLE",
            "RESET ALL",
            "SET SESSION AUTHORIZATION other_user",
            "SET LOCAL SESSION AUTHORIZATION other_user",
            "RESET SESSION AUTHORIZATION",
            "SET row_security = off",
            "SET \"row_security\" TO 'off'",
            "SET session_replication_role = replica",
            "SET session_replication_role TO 'replica'",
            "DISCARD ALL",
            "TRUNCATE TABLE public.orders",
            "SELECT set_config('role', 'proxima_tenant_other', false)",
            "SELECT pg_catalog.set_config('row_security','off',false)",
            "DO $body$ BEGIN SET ROLE proxima_tenant_other; END $body$",
            "CALL public.change_tenant_role()",
            "SET search_path = public",
            "SET LOCAL search_path TO public",
            "RESET search_path",
            "SET SCHEMA public",
            "RESET SCHEMA",
            "CREATE VIEW public.exposed_orders AS SELECT * FROM public.orders",
            "CREATE OR REPLACE VIEW public.exposed_orders AS SELECT * FROM public.orders",
            "CREATE MATERIALIZED VIEW public.exposed_orders AS SELECT * FROM public.orders",
            "ALTER VIEW public.exposed_orders SET (security_invoker = false)",
            "DROP VIEW public.exposed_orders",
            "REFRESH MATERIALIZED VIEW public.exposed_orders",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO PUBLIC",
            "ALTER TABLE public.orders DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE public.orders NO FORCE ROW LEVEL SECURITY",
            "CREATE POLICY broad_access ON public.orders USING (true)",
            "DROP POLICY tenant_guard ON public.orders",
            "ALTER ROLE proxima_tenant_a BYPASSRLS",
            "GRANT proxima_tenant_b TO proxima_tenant_a",
        ] {
            assert!(blocks_tenant_session_mutation(sql),"expected block: {sql}");
        }
    }

    #[test]
    fn allows_ordinary_queries_and_literals_that_mention_security_words() {
        for sql in [
            "SELECT * FROM public.orders",
            "SELECT 'SET ROLE other_user'",
            "UPDATE public.users SET role = 'operator'",
            "UPDATE public.orders SET status = 'SET ROLE'",
            "SELECT 'set_config(row_security)' AS example",
            "SET application_name = 'role=not_a_role_change'",
        ] {
            assert!(!blocks_tenant_session_mutation(sql),"unexpected block: {sql}");
        }
    }

    #[test]
    fn blocks_startup_security_options_even_with_quotes_and_spacing() {
        for options in [
            "-c role=proxima_tenant_other",
            "-c session_authorization=other_user",
            "-c row_security=off",
            "-c row_security = 'off'",
            "--session_replication_role=replica",
        ] {
            assert!(blocks_tenant_startup_options(options),"expected block: {options}");
        }
        assert!(blocks_tenant_startup_options("-c search_path=public"));
        assert!(!blocks_tenant_startup_options("-c application_name=my-service"));
    }

    #[test]
    fn extracts_simple_query_and_parse_frames() {
        let query=b"SELECT 1\0";let mut q=vec![b'Q'];q.extend_from_slice(&((query.len()+4) as i32).to_be_bytes());q.extend_from_slice(query);
        assert_eq!(sql_from_frontend_frame(&q),Some("SELECT 1"));
        let parse_payload=b"stmt\0SELECT 2\0\0\0";let mut p=vec![b'P'];p.extend_from_slice(&((parse_payload.len()+4) as i32).to_be_bytes());p.extend_from_slice(parse_payload);
        assert_eq!(sql_from_frontend_frame(&p),Some("SELECT 2"));
    }

    #[test]
    fn rejects_malformed_frames_and_tokenizer_failures() {
        assert_eq!(sql_from_frontend_frame(b"Q"),None);
        assert_eq!(sql_from_frontend_frame(b"S\0\0\0\x04"),None);
        assert!(blocks_tenant_session_mutation("SELECT 'unterminated"));
    }
}
