use sqlparser::ast::{Expr, ObjectName, Select, Visit, Visitor};
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;
use std::ops::ControlFlow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MysqlOperation {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MysqlPolicyError {
    EmptyStatement,
    MultipleStatements,
    InvalidSql(String),
    UnsupportedOperation,
}

impl std::fmt::Display for MysqlPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyStatement => write!(f, "empty SQL statement"),
            Self::MultipleStatements => write!(f, "multiple SQL statements are not permitted"),
            Self::InvalidSql(message) => write!(f, "SQL parsing failed: {message}"),
            Self::UnsupportedOperation => {
                write!(f, "SQL operation is not permitted by the MySQL policy")
            }
        }
    }
}

impl std::error::Error for MysqlPolicyError {}

#[derive(Default)]
struct AdmissionVisitor {
    rejected: bool,
}

impl Visitor for AdmissionVisitor {
    type Break = ();

    fn pre_visit_select(&mut self, select: &Select) -> ControlFlow<Self::Break> {
        if select.into.is_some() {
            self.rejected = true;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_relation(&mut self, relation: &ObjectName) -> ControlFlow<Self::Break> {
        let name = relation.to_string();
        // The initial tenant contract is a single default database. Fail
        // closed on qualified names and system schemas, including nested queries.
        if name.split('.').count() > 1 {
            self.rejected = true;
            return ControlFlow::Break(());
        }
        let schema = name.trim_matches('`').to_ascii_lowercase();
        if matches!(
            schema.as_str(),
            "mysql" | "information_schema" | "performance_schema" | "sys"
        ) {
            self.rejected = true;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }

    fn pre_visit_expr(&mut self, expr: &Expr) -> ControlFlow<Self::Break> {
        if let Expr::Function(function) = expr {
            let full_name = function.name.to_string().to_ascii_lowercase();
            let name = full_name
                .rsplit('.')
                .next()
                .unwrap_or(&full_name)
                .trim_matches('`');
            if matches!(
                name,
                "load_file"
                    | "sleep"
                    | "benchmark"
                    | "get_lock"
                    | "release_lock"
                    | "is_free_lock"
                    | "master_pos_wait"
                    | "sys_exec"
                    | "sys_eval"
            ) {
                self.rejected = true;
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    }
}

/// Parses one statement and classifies its operation, then applies conservative
/// AST restrictions. This is an admission layer, not the isolation boundary:
/// tenant-specific upstream credentials and database grants remain mandatory.
pub fn classify_statement(sql: &str) -> Result<MysqlOperation, MysqlPolicyError> {
    if sql.trim().is_empty() {
        return Err(MysqlPolicyError::EmptyStatement);
    }

    let dialect = MySqlDialect {};
    let statements = Parser::parse_sql(&dialect, sql)
        .map_err(|error| MysqlPolicyError::InvalidSql(error.to_string()))?;

    if statements.is_empty() {
        return Err(MysqlPolicyError::EmptyStatement);
    }
    if statements.len() != 1 {
        return Err(MysqlPolicyError::MultipleStatements);
    }

    let operation = match &statements[0] {
        sqlparser::ast::Statement::Query(_) => MysqlOperation::Read,
        sqlparser::ast::Statement::Insert(_)
        | sqlparser::ast::Statement::Update(_)
        | sqlparser::ast::Statement::Delete(_) => MysqlOperation::Write,
        _ => return Err(MysqlPolicyError::UnsupportedOperation),
    };

    let mut visitor = AdmissionVisitor::default();
    let _ = statements.visit(&mut visitor);
    if visitor.rejected {
        return Err(MysqlPolicyError::UnsupportedOperation);
    }

    Ok(operation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_select_as_read() {
        assert_eq!(
            classify_statement("SELECT id, name FROM customers WHERE id = 7"),
            Ok(MysqlOperation::Read)
        );
    }

    #[test]
    fn accepts_cte_select_as_read() {
        assert_eq!(
            classify_statement("WITH recent AS (SELECT id FROM customers) SELECT id FROM recent"),
            Ok(MysqlOperation::Read)
        );
    }

    #[test]
    fn accepts_insert_as_write() {
        assert_eq!(
            classify_statement("INSERT INTO customers (name) VALUES ('test')"),
            Ok(MysqlOperation::Write)
        );
    }

    #[test]
    fn accepts_update_as_write() {
        assert_eq!(
            classify_statement("UPDATE customers SET name = 'updated' WHERE id = 1"),
            Ok(MysqlOperation::Write)
        );
    }

    #[test]
    fn accepts_delete_as_write() {
        assert_eq!(
            classify_statement("DELETE FROM customers WHERE id = 1"),
            Ok(MysqlOperation::Write)
        );
    }

    #[test]
    fn rejects_multiple_statements() {
        assert_eq!(
            classify_statement("SELECT 1; DELETE FROM customers"),
            Err(MysqlPolicyError::MultipleStatements)
        );
    }

    #[test]
    fn rejects_database_switching() {
        assert_eq!(
            classify_statement("USE another_database"),
            Err(MysqlPolicyError::UnsupportedOperation)
        );
    }

    #[test]
    fn rejects_session_mutation() {
        assert_eq!(
            classify_statement("SET SESSION sql_mode = 'ANSI'"),
            Err(MysqlPolicyError::UnsupportedOperation)
        );
    }

    #[test]
    fn rejects_ddl() {
        assert_eq!(
            classify_statement("DROP TABLE customers"),
            Err(MysqlPolicyError::UnsupportedOperation)
        );
    }

    #[test]
    fn rejects_select_into() {
        assert!(
            classify_statement("SELECT id FROM customers INTO OUTFILE '/tmp/export.txt'").is_err(),
            "SELECT INTO OUTFILE must fail closed regardless of parser error classification"
        );
    }

    #[test]
    fn rejects_qualified_cross_database_references() {
        assert_eq!(
            classify_statement("SELECT * FROM tenant_b.records"),
            Err(MysqlPolicyError::UnsupportedOperation)
        );
    }

    #[test]
    fn rejects_system_schema_references() {
        assert_eq!(
            classify_statement("SELECT user FROM mysql.user"),
            Err(MysqlPolicyError::UnsupportedOperation)
        );
    }

    #[test]
    fn rejects_privileged_and_resource_intensive_functions() {
        for sql in [
            "SELECT LOAD_FILE('/etc/passwd')",
            "SELECT SLEEP(10)",
            "SELECT BENCHMARK(1000000, SHA2('x', 256))",
            "SELECT GET_LOCK('proxima', 1)",
        ] {
            assert_eq!(
                classify_statement(sql),
                Err(MysqlPolicyError::UnsupportedOperation),
                "unexpected admission for: {sql}"
            );
        }
    }

    #[test]
    fn rejects_malformed_sql() {
        assert!(matches!(
            classify_statement("SELECT FROM WHERE"),
            Err(MysqlPolicyError::InvalidSql(_))
        ));
    }

    #[test]
    fn rejects_empty_sql() {
        assert_eq!(
            classify_statement("   "),
            Err(MysqlPolicyError::EmptyStatement)
        );
    }
}
