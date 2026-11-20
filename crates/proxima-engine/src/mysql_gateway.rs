use crate::mysql_identity::MysqlIdentityRegistry;
use crate::mysql_policy::classify_statement;
use crate::mysql_session::MysqlConnectionIdentity;
use crate::mysql_upstream::MysqlUpstream;

use futures_util::StreamExt;
use mysql_async::prelude::Queryable;
use mysql_async::{Conn, Row, Statement, Value as UpstreamValue};

use opensrv_mysql::{
    AsyncMysqlIntermediary, AsyncMysqlShim, Column, ColumnFlags, ColumnType, ErrorKind, InitWriter,
    IntermediaryOptions, OkResponse, ParamParser, QueryResultWriter, StatementMetaWriter,
    StatusFlags, ValueInner,
};

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};
use tokio::task;
use uuid::Uuid;

const SERVER_VERSION: &str = "8.0.0-agata-proxima";
const UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 10;
const DEFAULT_MAX_CONNECTIONS: usize = 128;

/// One upstream connection and its prepared statements belong to one
/// authenticated client session. The pool is retained for the lifetime
/// of the session; the checked-out connection is never returned to it.
struct MysqlUpstreamSession {
    _pool: MysqlUpstream,
    connection: Conn,
    statements: HashMap<u32, Statement>,
}

impl MysqlUpstreamSession {
    fn new(pool: MysqlUpstream, connection: Conn) -> Self {
        Self {
            _pool: pool,
            connection,
            statements: HashMap::new(),
        }
    }
}

/// One gateway session represents exactly one client connection.
///
/// The authenticated principal is immutable. The upstream connection
/// is established only after successful authentication and remains
/// bound to that principal for the session lifetime.
struct MysqlGatewaySession {
    registry: Arc<MysqlIdentityRegistry>,
    identity: MysqlConnectionIdentity,
    upstream: Mutex<Option<MysqlUpstreamSession>>,
    salt: [u8; 20],
}

impl MysqlGatewaySession {
    fn new(registry: Arc<MysqlIdentityRegistry>) -> Self {
        Self {
            registry,
            identity: MysqlConnectionIdentity::new(),
            upstream: Mutex::new(None),
            salt: {
                let first = Uuid::new_v4().simple().to_string();
                let second = Uuid::new_v4().simple().to_string();
                let combined = format!("{first}{second}");
                let mut salt = [0u8; 20];
                salt.copy_from_slice(&combined.as_bytes()[..20]);
                salt
            },
        }
    }

    fn authenticated(&self) -> bool {
        self.identity.is_authenticated()
    }

    async fn upstream_ready(&self) -> bool {
        self.upstream.lock().await.is_some()
    }
}

/// Convert a protocol parameter into an owned mysql_async value.
///
/// Date/time binary parameter payloads are deliberately rejected until
/// their complete binary encodings are explicitly validated and decoded.
/// Treating binary date/time payloads as ordinary strings would be unsafe.
fn convert_parameter(value: ValueInner<'_>) -> Result<UpstreamValue, ()> {
    match value {
        ValueInner::NULL => Ok(UpstreamValue::NULL),
        ValueInner::Bytes(bytes) => Ok(UpstreamValue::Bytes(bytes.to_vec())),
        ValueInner::Int(value) => Ok(UpstreamValue::Int(value)),
        ValueInner::UInt(value) => Ok(UpstreamValue::UInt(value)),
        ValueInner::Double(value) => Ok(UpstreamValue::Double(value)),
        ValueInner::Date(_) | ValueInner::Time(_) | ValueInner::Datetime(_) => Err(()),
    }
}

/// opensrv-mysql 0.7.0's ParamParser contains unchecked parsing paths.
/// Catch parser panics at this protocol boundary so malformed client
/// packets cannot unwind through the gateway session task.
fn decode_parameters(params: ParamParser<'_>) -> Result<Vec<UpstreamValue>, ()> {
    catch_unwind(AssertUnwindSafe(|| {
        params
            .into_iter()
            .map(|parameter| convert_parameter(parameter.value.into_inner()))
            .collect::<Result<Vec<_>, _>>()
    }))
    .unwrap_or(Err(()))
}

/// Convert upstream values to the text representation used by this
/// gateway's result metadata. NULL remains NULL.
fn upstream_value_to_text(value: UpstreamValue) -> Option<String> {
    match value {
        UpstreamValue::NULL => None,

        UpstreamValue::Bytes(bytes) => match String::from_utf8(bytes.clone()) {
            Ok(text) => Some(text),
            Err(_) => Some(format!("0x{}", hex::encode(bytes))),
        },

        UpstreamValue::Int(value) => Some(value.to_string()),
        UpstreamValue::UInt(value) => Some(value.to_string()),
        UpstreamValue::Float(value) => Some(value.to_string()),
        UpstreamValue::Double(value) => Some(value.to_string()),

        UpstreamValue::Date(year, month, day, hour, minute, second, micros) => {
            if hour == 0 && minute == 0 && second == 0 && micros == 0 {
                Some(format!("{year:04}-{month:02}-{day:02}"))
            } else if micros == 0 {
                Some(format!(
                    "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
                ))
            } else {
                Some(format!(
                    "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{micros:06}"
                ))
            }
        }

        UpstreamValue::Time(negative, days, hours, minutes, seconds, micros) => {
            let total_hours = days * 24 + u32::from(hours);
            let sign = if negative { "-" } else { "" };

            if micros == 0 {
                Some(format!("{sign}{total_hours:02}:{minutes:02}:{seconds:02}"))
            } else {
                Some(format!(
                    "{sign}{total_hours:02}:{minutes:02}:{seconds:02}.{micros:06}"
                ))
            }
        }
    }
}

/// Preserve the upstream MySQL protocol type code. Both driver and server
/// enums follow the MySQL wire-protocol numeric assignments; unknown future
/// types fall back to VAR_STRING rather than emitting an invalid type code.
fn output_column_type(column_type: mysql_async::consts::ColumnType) -> ColumnType {
    ColumnType::try_from(column_type as u8).unwrap_or(ColumnType::MYSQL_TYPE_VAR_STRING)
}

fn output_column(column: &mysql_async::Column) -> Column {
    Column {
        table: column.table_str().into_owned(),
        column: column.name_str().into_owned(),
        coltype: output_column_type(column.column_type()),
        colflags: ColumnFlags::empty(),
    }
}

#[async_trait::async_trait]
impl<W> AsyncMysqlShim<W> for MysqlGatewaySession
where
    W: tokio::io::AsyncWrite + Send + Unpin,
{
    type Error = io::Error;

    fn version(&self) -> String {
        SERVER_VERSION.to_string()
    }

    fn connect_id(&self) -> u32 {
        let uuid = Uuid::new_v4();
        let bytes = uuid.as_bytes();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn default_auth_plugin(&self) -> &str {
        "mysql_native_password"
    }

    async fn auth_plugin_for_username(&self, _user: &[u8]) -> &str {
        "mysql_native_password"
    }

    fn salt(&self) -> [u8; 20] {
        self.salt
    }

    async fn authenticate(
        &self,
        auth_plugin: &str,
        username: &[u8],
        salt: &[u8],
        auth_data: &[u8],
    ) -> bool {
        if self.authenticated() || self.upstream_ready().await {
            return false;
        }

        let Some(principal) = self
            .registry
            .authenticate(auth_plugin, username, salt, auth_data)
        else {
            return false;
        };

        // The registry entry selects the only upstream identity this
        // client session is permitted to use.
        let pool = match MysqlUpstream::from_url(&principal.upstream_url) {
            Ok(pool) => pool,
            Err(_) => return false,
        };

        // Establish the real upstream connection before accepting
        // authentication. All later work uses this exact connection.
        let connection = match tokio::time::timeout(
            std::time::Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
            pool.get_connection(),
        )
        .await
        {
            Ok(Ok(connection)) => connection,
            _ => return false,
        };

        // Check the database selected by the live upstream session as a second
        // guard against a registry/driver configuration mismatch.
        let selected_database: Option<String> = match tokio::time::timeout(
            std::time::Duration::from_secs(UPSTREAM_CONNECT_TIMEOUT_SECS),
            connection.query_first("SELECT DATABASE()"),
        )
        .await
        {
            Ok(Ok(database)) => database,
            _ => return false,
        };
        if selected_database.as_deref() != Some(principal.database.as_str()) {
            tracing::warn!(
                username = %principal.username,
                expected_database = %principal.database,
                selected_database = ?selected_database,
                "MySQL upstream database did not match the tenant registry"
            );
            return false;
        }

        if self.identity.bind_authenticated(principal).is_err() {
            return false;
        }

        let mut guard = self.upstream.lock().await;

        if guard.is_some() {
            return false;
        }

        *guard = Some(MysqlUpstreamSession::new(pool, connection));

        true
    }

    async fn on_prepare<'a>(
        &'a mut self,
        query: &'a str,
        info: StatementMetaWriter<'a, W>,
    ) -> Result<(), Self::Error> {
        if !self.authenticated() {
            return info
                .error(
                    ErrorKind::ER_ACCESS_DENIED_ERROR,
                    &b"authentication required"[..],
                )
                .await;
        }

        if classify_statement(query).is_err() {
            return info
                .error(
                    ErrorKind::ER_NOT_SUPPORTED_YET,
                    &b"prepared statement rejected by Proxima SQL admission policy"[..],
                )
                .await;
        }

        let mut guard = self.upstream.lock().await;
        let Some(session) = guard.as_mut() else {
            return info
                .error(
                    ErrorKind::ER_UNKNOWN_ERROR,
                    &b"tenant upstream connection unavailable"[..],
                )
                .await;
        };

        let statement = match session.connection.prep(query).await {
            Ok(statement) => statement,
            Err(_) => {
                return info
                    .error(
                        ErrorKind::ER_UNKNOWN_ERROR,
                        &b"upstream statement preparation failed"[..],
                    )
                    .await;
            }
        };

        let client_statement_id = statement.id();

        if session.statements.contains_key(&client_statement_id) {
            let _ = session.connection.close(statement).await;
            return info
                .error(
                    ErrorKind::ER_UNKNOWN_ERROR,
                    &b"prepared statement identifier collision"[..],
                )
                .await;
        }

        let parameter_columns: Vec<Column> = statement.params().iter().map(output_column).collect();

        let result_metadata = statement.columns();

        let result_columns: Vec<Column> = result_metadata.iter().map(output_column).collect();

        session.statements.insert(client_statement_id, statement);

        let reply_result = info
            .reply(
                client_statement_id,
                parameter_columns.iter(),
                result_columns.iter(),
            )
            .await;

        if reply_result.is_err() {
            if let Some(statement) = session.statements.remove(&client_statement_id) {
                let _ = session.connection.close(statement).await;
            }
        }

        reply_result
    }

    async fn on_execute<'a>(
        &'a mut self,
        id: u32,
        params: ParamParser<'a>,
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error> {
        if !self.authenticated() {
            return results
                .error(
                    ErrorKind::ER_ACCESS_DENIED_ERROR,
                    &b"authentication required"[..],
                )
                .await;
        }

        let values = match decode_parameters(params) {
            Ok(values) => values,
            Err(()) => {
                return results
                    .error(
                        ErrorKind::ER_WRONG_ARGUMENTS,
                        &b"invalid or unsupported prepared statement parameters"[..],
                    )
                    .await;
            }
        };

        let mut guard = self.upstream.lock().await;
        let Some(session) = guard.as_mut() else {
            return results
                .error(
                    ErrorKind::ER_UNKNOWN_ERROR,
                    &b"tenant upstream connection unavailable"[..],
                )
                .await;
        };

        let Some(statement) = session.statements.get(&id) else {
            return results
                .error(
                    ErrorKind::ER_UNKNOWN_STMT_HANDLER,
                    &b"unknown prepared statement for this tenant session"[..],
                )
                .await;
        };

        if values.len() != statement.num_params() as usize {
            return results
                .error(
                    ErrorKind::ER_WRONG_ARGUMENTS,
                    &b"prepared statement parameter count mismatch"[..],
                )
                .await;
        }

        let mut upstream_result = match session.connection.exec_iter(statement, values).await {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "MySQL upstream prepared statement execution failed"
                );

                return results
                    .error(
                        ErrorKind::ER_UNKNOWN_ERROR,
                        &b"upstream prepared statement execution failed"[..],
                    )
                    .await;
            }
        };

        let upstream_columns = upstream_result.columns_ref();

        if upstream_columns.is_empty() {
            let affected_rows = upstream_result.affected_rows();
            let last_insert_id = upstream_result.last_insert_id().unwrap_or(0);
            let warnings = upstream_result.warnings();

            if upstream_result.drop_result().await.is_err() {
                return results
                    .error(
                        ErrorKind::ER_UNKNOWN_ERROR,
                        &b"upstream result completion failed"[..],
                    )
                    .await;
            }

            return results
                .completed(OkResponse {
                    header: 0x00,
                    affected_rows,
                    last_insert_id,
                    status_flags: StatusFlags::empty(),
                    warnings,
                    info: String::new(),
                    session_state_info: String::new(),
                })
                .await;
        }

        let output_columns: Vec<Column> = upstream_columns.iter().map(output_column).collect();

        let mut output = results.start(&output_columns).await?;

        let mut rows = match upstream_result.stream::<Row>().await {
            Ok(Some(rows)) => rows,
            Ok(None) => return output.finish().await,
            Err(_) => {
                return output
                    .finish_error(
                        ErrorKind::ER_UNKNOWN_ERROR,
                        &b"upstream prepared result stream failed".to_vec(),
                    )
                    .await;
            }
        };

        while let Some(row_result) = rows.next().await {
            let row = match row_result {
                Ok(row) => row,
                Err(_) => {
                    return output
                        .finish_error(
                            ErrorKind::ER_UNKNOWN_ERROR,
                            &b"upstream row retrieval failed".to_vec(),
                        )
                        .await;
                }
            };

            let values: Vec<Option<String>> = row
                .unwrap()
                .into_iter()
                .map(upstream_value_to_text)
                .collect();

            output.write_row(values).await?;
        }

        output.finish().await
    }

    async fn on_close<'a>(&'a mut self, stmt: u32)
    where
        W: 'async_trait,
    {
        let mut guard = self.upstream.lock().await;

        if let Some(session) = guard.as_mut() {
            if let Some(statement) = session.statements.remove(&stmt) {
                let _ = session.connection.close(statement).await;
            }
        }
    }

    async fn on_init<'a>(
        &'a mut self,
        database: &'a str,
        writer: InitWriter<'a, W>,
    ) -> Result<(), Self::Error> {
        match self.identity.authorize_database(database) {
            Ok(()) => writer.ok().await,
            Err(_) => {
                writer
                    .error(
                        ErrorKind::ER_DBACCESS_DENIED_ERROR,
                        &b"database access denied by Proxima tenant policy"[..],
                    )
                    .await
            }
        }
    }

    async fn on_query<'a>(
        &'a mut self,
        query: &'a str,
        results: QueryResultWriter<'a, W>,
    ) -> Result<(), Self::Error> {
        if !self.authenticated() {
            return results
                .error(
                    ErrorKind::ER_ACCESS_DENIED_ERROR,
                    &b"authentication required"[..],
                )
                .await;
        }

        if classify_statement(query).is_err() {
            return results
                .error(
                    ErrorKind::ER_NOT_SUPPORTED_YET,
                    &b"statement rejected by Proxima SQL admission policy"[..],
                )
                .await;
        }

        let mut guard = self.upstream.lock().await;
        let Some(session) = guard.as_mut() else {
            return results
                .error(
                    ErrorKind::ER_UNKNOWN_ERROR,
                    &b"tenant upstream connection unavailable"[..],
                )
                .await;
        };

        let mut upstream_result = match session.connection.query_iter(query).await {
            Ok(result) => result,
            Err(_) => {
                return results
                    .error(ErrorKind::ER_UNKNOWN_ERROR, &b"upstream query failed"[..])
                    .await;
            }
        };

        let upstream_columns = upstream_result.columns_ref();

        if upstream_columns.is_empty() {
            let affected_rows = upstream_result.affected_rows();
            let last_insert_id = upstream_result.last_insert_id().unwrap_or(0);
            let warnings = upstream_result.warnings();

            if upstream_result.drop_result().await.is_err() {
                return results
                    .error(
                        ErrorKind::ER_UNKNOWN_ERROR,
                        &b"upstream result completion failed"[..],
                    )
                    .await;
            }

            return results
                .completed(OkResponse {
                    header: 0x00,
                    affected_rows,
                    last_insert_id,
                    status_flags: StatusFlags::empty(),
                    warnings,
                    info: String::new(),
                    session_state_info: String::new(),
                })
                .await;
        }

        let output_columns: Vec<Column> = upstream_columns.iter().map(output_column).collect();

        let mut output = results.start(&output_columns).await?;

        let mut rows = match upstream_result.stream::<Row>().await {
            Ok(Some(rows)) => rows,
            Ok(None) => return output.finish().await,
            Err(_) => {
                return output
                    .finish_error(
                        ErrorKind::ER_UNKNOWN_ERROR,
                        &b"upstream result stream failed".to_vec(),
                    )
                    .await;
            }
        };

        while let Some(row_result) = rows.next().await {
            let row = match row_result {
                Ok(row) => row,
                Err(_) => {
                    return output
                        .finish_error(
                            ErrorKind::ER_UNKNOWN_ERROR,
                            &b"upstream row retrieval failed".to_vec(),
                        )
                        .await;
                }
            };

            let values: Vec<Option<String>> = row
                .unwrap()
                .into_iter()
                .map(upstream_value_to_text)
                .collect();

            output.write_row(values).await?;
        }

        output.finish().await
    }
}

/// Accept only loopback binding in this first gateway release.
/// A remote listener requires client-facing TLS and hardened deployment
/// configuration before it can be enabled.
pub async fn run_mysql_gateway(
    address: SocketAddr,
    registry: Arc<MysqlIdentityRegistry>,
) -> io::Result<()> {
    if !address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Proxima MySQL gateway currently requires a loopback bind address",
        ));
    }

    let max_connections = std::env::var("PROXIMA_MYSQL_MAX_CONNECTIONS")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?
        .unwrap_or(DEFAULT_MAX_CONNECTIONS);
    if max_connections == 0 || max_connections > 65_536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PROXIMA_MYSQL_MAX_CONNECTIONS must be between 1 and 65536",
        ));
    }

    let listener = TcpListener::bind(address).await?;
    let connection_slots = Arc::new(Semaphore::new(max_connections));

    tracing::info!(
        address = %listener.local_addr()?,
        max_connections,
        "Proxima MySQL gateway listening"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = match Arc::clone(&connection_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(
                    peer = %peer,
                    max_connections,
                    "MySQL connection rejected because the gateway connection limit is reached"
                );
                drop(stream);
                continue;
            }
        };
        let registry = Arc::clone(&registry);

        task::spawn(async move {
            let _connection_permit = permit;
            let (reader, writer) = stream.into_split();
            let session = MysqlGatewaySession::new(registry);

            let options = IntermediaryOptions {
                process_use_statement_on_query: false,
                reject_connection_on_dbname_absence: true,
            };

            if let Err(error) =
                AsyncMysqlIntermediary::run_with_options(session, reader, writer, &options).await
            {
                tracing::debug!(
                    peer = %peer,
                    error = %error,
                    "MySQL client session ended"
                );
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_upstream_column_type_codes() {
        assert_eq!(
            output_column_type(mysql_async::consts::ColumnType::MYSQL_TYPE_LONG),
            ColumnType::MYSQL_TYPE_LONG
        );
        assert_eq!(
            output_column_type(mysql_async::consts::ColumnType::MYSQL_TYPE_NEWDECIMAL),
            ColumnType::MYSQL_TYPE_NEWDECIMAL
        );
        assert_eq!(
            output_column_type(mysql_async::consts::ColumnType::MYSQL_TYPE_BLOB),
            ColumnType::MYSQL_TYPE_BLOB
        );
    }

    #[test]
    fn preserves_null_values() {
        assert_eq!(upstream_value_to_text(UpstreamValue::NULL), None);
    }

    #[test]
    fn converts_integer_values() {
        assert_eq!(
            upstream_value_to_text(UpstreamValue::Int(-42)),
            Some("-42".to_string())
        );
    }

    #[test]
    fn converts_unsigned_values() {
        assert_eq!(
            upstream_value_to_text(UpstreamValue::UInt(42)),
            Some("42".to_string())
        );
    }

    #[test]
    fn preserves_valid_utf8_bytes() {
        assert_eq!(
            upstream_value_to_text(UpstreamValue::Bytes(b"tenant-data".to_vec())),
            Some("tenant-data".to_string())
        );
    }

    #[test]
    fn encodes_non_utf8_bytes_without_lossy_replacement() {
        assert_eq!(
            upstream_value_to_text(UpstreamValue::Bytes(vec![0xff, 0x00])),
            Some("0xff00".to_string())
        );
    }

    #[test]
    fn converts_signed_prepared_parameter() {
        assert!(matches!(
            convert_parameter(ValueInner::Int(-42)),
            Ok(UpstreamValue::Int(-42))
        ));
    }

    #[test]
    fn converts_unsigned_prepared_parameter() {
        assert!(matches!(
            convert_parameter(ValueInner::UInt(42)),
            Ok(UpstreamValue::UInt(42))
        ));
    }

    #[test]
    fn converts_string_prepared_parameter() {
        assert!(matches!(
            convert_parameter(ValueInner::Bytes(b"tenant-a")),
            Ok(UpstreamValue::Bytes(value)) if value == b"tenant-a"
        ));
    }

    #[test]
    fn converts_null_prepared_parameter() {
        assert!(matches!(
            convert_parameter(ValueInner::NULL),
            Ok(UpstreamValue::NULL)
        ));
    }

    #[test]
    fn rejects_unvalidated_date_parameter_encoding() {
        assert!(convert_parameter(ValueInner::Date(&[4, 0, 0, 0])).is_err());
    }
}

