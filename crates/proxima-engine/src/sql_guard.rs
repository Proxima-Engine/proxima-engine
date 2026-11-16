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
    let Ok(statements) = Parser::parse_sql(&dialect, sql) else {
        return false;
    };

    statements.iter().any(|statement| {
        let normalized = statement
            .to_string()
            .to_ascii_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let compact = normalized.replace(' ', "");
        compact.starts_with("setrole")
            || compact.starts_with("setlocalrole")
            || compact.starts_with("setsessionauthorization")
            || compact.starts_with("setlocalsessionauthorization")
            || compact.starts_with("resetrole")
            || compact.starts_with("resetsessionauthorization")
            || compact.starts_with("discardall")
            || compact.starts_with("setrow_security=off")
            || compact.starts_with("setrow_securitytooff")
            || compact.starts_with("setsession_replication_role=replica")
            || compact.starts_with("setsession_replication_roleto'replica'")
    })
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
        ] {
            assert!(blocks_tenant_session_mutation(sql), "expected block: {sql}");
        }
    }

    #[test]
    fn allows_ordinary_queries_and_literals_that_mention_role_commands() {
        assert!(!blocks_tenant_session_mutation("SELECT * FROM public.orders"));
        assert!(!blocks_tenant_session_mutation("SELECT 'SET ROLE other_user'"));
        assert!(!blocks_tenant_session_mutation("UPDATE public.orders SET status = 'SET ROLE'"));
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
