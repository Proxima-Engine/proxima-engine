use sqlparser::{
    dialect::PostgreSqlDialect,
    parser::Parser,
};

/// Returns true only for parsed statements that can change the authenticated
/// PostgreSQL role or disable row-security behavior for a tenant-bound session.
/// Parse failures are deliberately not classified as safe or blocked; PostgreSQL
/// remains the syntax authority for the full PostgreSQL dialect.
pub fn blocks_tenant_session_mutation(sql: &str) -> bool {
    let dialect = PostgreSqlDialect {};
    // Parse first for PostgreSQL syntax awareness. Token inspection below also
    // catches security commands that a parser version may not model yet.
    let _parsed = Parser::parse_sql(&dialect, sql);
    let Ok(tokens) = sqlparser::tokenizer::Tokenizer::new(&dialect, sql).tokenize() else {
        return false;
    };
    let tokens: Vec<String> = tokens
        .iter()
        .map(|token| token.to_string().to_ascii_lowercase().replace('"', ""))
        .collect();
    let at = |index: usize, expected: &str| tokens.get(index).is_some_and(|value| value == expected);

    if tokens.iter().any(|token| token.ends_with("set_config")) {
        return true;
    }
    for index in 0..tokens.len() {
        let statement_start = index == 0 || at(index - 1, ";");
        if statement_start && (at(index, "do") || at(index, "call") || at(index, "truncate") || at(index, "discard") && at(index + 1, "all")) {
            return true;
        }
        if statement_start && at(index, "reset") && (at(index + 1, "role")
            || at(index + 1, "session") && at(index + 2, "authorization")) {
            return true;
        }
        if statement_start && at(index, "set") {
            let mut cursor = index + 1;
            if at(cursor, "session") && at(cursor + 1, "authorization") { return true; }
            if at(cursor, "session") || at(cursor, "local") { cursor += 1; }
            if at(cursor, "role") { return true; }
            if (at(cursor, "row_security") && (at(cursor + 1, "=") || at(cursor + 1, "to")) && at(cursor + 2, "off"))
                || (at(cursor, "session_replication_role") && (at(cursor + 1, "=") || at(cursor + 1, "to")) && at(cursor + 2, "replica")) {
                return true;
            }
        }
    }
    false
}

/// Detects startup -c options that could override the tenant-bound role or
/// disable row-security behavior before the first SQL frame is received.
pub fn blocks_tenant_startup_options(options: &str) -> bool {
    let tokens: Vec<&str> = options.split_whitespace().collect();
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index].trim_matches(|character| character == '\'' || character == '"');
        let assignment = if token == "-c" || token == "--set" {
            index += 1;
            tokens.get(index).copied()
        } else if let Some(value) = token.strip_prefix("-c") {
            Some(value)
        } else if let Some(value) = token.strip_prefix("--") {
            Some(value)
        } else {
            None
        };
        if let Some(assignment) = assignment {
            let assignment = assignment.trim_matches(|character| character == '\'' || character == '"');
            let mut pair = assignment.splitn(2, '=');
            let key = pair.next().unwrap_or("").to_ascii_lowercase();
            let value = pair.next().unwrap_or("").trim_matches(|character| character == '\'' || character == '"').to_ascii_lowercase();
            if key == "role" || key == "session_authorization"
                || key == "row_security" && value == "off"
                || key == "session_replication_role" && value == "replica" {
                return true;
            }
        }
        index += 1;
    }
    false
}

/// Extracts SQL text from PostgreSQL simple-query (Q) and Parse (P) frames.
/// The supplied slice must contain one complete frontend frame.
pub fn sql_from_frontend_frame(frame: &[u8]) -> Option<&str> {
    if frame.len() < 5 {
        return None;
    }
    let length = i32::from_be_bytes(frame[1..5].try_into().ok()?);
    if length < 4 || frame.len() != length as usize + 1 {
        return None;
    }
    let payload = &frame[5..];
    match frame[0] {
        b'Q' => c_string(payload),
        b'P' => {
            let (_, remainder) = split_c_string(payload)?;
            c_string(remainder)
        }
        _ => None,
    }
}

fn c_string(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&bytes[..end]).ok()
}

fn split_c_string(bytes: &[u8]) -> Option<(&str, &[u8])> {
    let end = bytes.iter().position(|byte| *byte == 0)?;
    Some((std::str::from_utf8(&bytes[..end]).ok()?, &bytes[end + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_role_switches_and_row_security_disable() {
        for sql in [
            "SET ROLE proxima_tenant_other",
            "SET LOCAL ROLE proxima_tenant_other",
            "RESET ROLE",
            "SET SESSION AUTHORIZATION other_user",
            "RESET SESSION AUTHORIZATION",
            "SET row_security = off",
            "SET session_replication_role = replica",
            "DISCARD ALL",
            "TRUNCATE TABLE public.orders",
        ] {
            assert!(blocks_tenant_session_mutation(sql), "expected block: {sql}");
        }
    }

    #[test]
    fn allows_ordinary_queries_and_literals_that_mention_role_commands() {
        assert!(!blocks_tenant_session_mutation("SELECT * FROM public.orders"));
        assert!(!blocks_tenant_session_mutation("SELECT 'SET ROLE other_user'"));
        assert!(!blocks_tenant_session_mutation("UPDATE public.users SET role = 'operator'"));
        assert!(!blocks_tenant_session_mutation("UPDATE public.orders SET status = 'SET ROLE'"));
    }

    #[test]
    fn blocks_security_sensitive_startup_options() {
        for options in [
            "-c role=proxima_tenant_other",
            "-c session_authorization=other_user",
            "-c row_security=off",
            "--session_replication_role=replica",
        ] {
            assert!(blocks_tenant_startup_options(options), "expected block: {options}");
        }
        assert!(!blocks_tenant_startup_options("-c application_name=my-service -c search_path=public"));
    }

    #[test]
    fn extracts_simple_query_and_parse_frames() {
        let query = b"SELECT 1\0";
        let mut q = vec![b'Q'];
        q.extend_from_slice(&((query.len() + 4) as i32).to_be_bytes());
        q.extend_from_slice(query);
        assert_eq!(sql_from_frontend_frame(&q), Some("SELECT 1"));

        let parse_payload = b"stmt\0SELECT 2\0\0\0";
        let mut p = vec![b'P'];
        p.extend_from_slice(&((parse_payload.len() + 4) as i32).to_be_bytes());
        p.extend_from_slice(parse_payload);
        assert_eq!(sql_from_frontend_frame(&p), Some("SELECT 2"));
    }

    #[test]
    fn ignores_non_query_frames_and_incomplete_frames() {
        assert_eq!(sql_from_frontend_frame(b"Q"), None);
        assert_eq!(sql_from_frontend_frame(b"S\0\0\0\x04"), None);
    }
}
