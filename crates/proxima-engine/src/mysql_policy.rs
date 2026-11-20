use sqlparser::ast::Statement;
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::Parser;

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

/// Parses one MySQL statement and classifies its operation.
///
/// This is an initial admission gate, not the complete tenant-isolation
/// decision. Object-level authorization and tenant-specific upstream
/// credentials must be enforced before forwarding any accepted statement.
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

    match &statements[0] {
        Statement::Query(_) => Ok(MysqlOperation::Read),
        Statement::Insert(_) | Statement::Update(_) | Statement::Delete(_) => {
            Ok(MysqlOperation::Write)
        }
        _ => Err(MysqlPolicyError::UnsupportedOperation),
    }
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
