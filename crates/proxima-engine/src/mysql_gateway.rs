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
    StatusFlags, ToMysqlValue, ValueInner,
};

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{Mutex, Semaphore};
use tokio::task;
use uuid::Uuid;

const SERVER_VERSION: &str = "8.0.0-agata-proxima";
const UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 10;
const QUERY_TIMEOUT_SECS: u64 = 30;
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
/// Date/time binary parameter payloads are decoded according to the MySQL
/// binary protocol and rejected when their lengths or component ranges are invalid.
fn decode_date_payload(bytes: &[u8]) -> Result<(u16, u8, u8), ()> {
    if bytes.is_empty() { return Ok((0, 0, 0)); }
    if bytes.len() != 4 { return Err(()); }
    let year = u16::from_le_bytes([bytes[0], bytes[1]]);
    let (month, day) = (bytes[2], bytes[3]);
    if month > 12 || day > 31 { return Err(()); }
    Ok((year, month, day))
}

fn decode_datetime_payload(bytes: &[u8]) -> Result<(u16, u8, u8, u8, u8, u8, u32), ()> {
    if bytes.is_empty() { return Ok((0, 0, 0, 0, 0, 0, 0)); }
    if !matches!(bytes.len(), 4 | 7 | 11) { return Err(()); }
    let (year, month, day) = decode_date_payload(&bytes[..4])?;
    let (hour, minute, second) = if bytes.len() >= 7 { (bytes[4], bytes[5], bytes[6]) } else { (0, 0, 0) };
    let micros = if bytes.len() == 11 { u32::from_le_bytes(bytes[7..11].try_into().map_err(|_| ())?) } else { 0 };
    if hour > 23 || minute > 59 || second > 59 || micros > 999_999 { return Err(()); }
    Ok((year, month, day, hour, minute, second, micros))
}

fn decode_time_payload(bytes: &[u8]) -> Result<(bool, u32, u8, u8, u8, u32), ()> {
    if bytes.is_empty() { return Ok((false, 0, 0, 0, 0, 0)); }
    if !matches!(bytes.len(), 8 | 12) || bytes[0] > 1 { return Err(()); }
    let days = u32::from_le_bytes(bytes[1..5].try_into().map_err(|_| ())?);
    let (hours, minutes, seconds) = (bytes[5], bytes[6], bytes[7]);
    let micros = if bytes.len() == 12 { u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| ())?) } else { 0 };
    if hours > 23 || minutes > 59 || seconds > 59 || micros > 999_999 { return Err(()); }
    Ok((bytes[0] == 1, days, hours, minutes, seconds, micros))
}

fn convert_parameter(value: ValueInner<'_>) -> Result<UpstreamValue, ()> {
    match value {
        ValueInner::NULL => Ok(UpstreamValue::NULL),
        ValueInner::Bytes(bytes) => Ok(UpstreamValue::Bytes(bytes.to_vec())),
        ValueInner::Int(value) => Ok(UpstreamValue::Int(value)),
        ValueInner::UInt(value) => Ok(UpstreamValue::UInt(value)),
        ValueInner::Double(value) => Ok(UpstreamValue::Double(value)),
        ValueInner::Date(bytes) => {
            let (year, month, day) = decode_date_payload(bytes)?;
            Ok(UpstreamValue::Date(year, month, day, 0, 0, 0, 0))
        }
        ValueInner::Datetime(bytes) => {
            let (year, month, day, hour, minute, second, micros) = decode_datetime_payload(bytes)?;
            Ok(UpstreamValue::Date(year, month, day, hour, minute, second, micros))
        }
        ValueInner::Time(bytes) => {
            let (negative, days, hours, minutes, seconds, micros) = decode_time_payload(bytes)?;
            Ok(UpstreamValue::Time(negative, days, hours, minutes, seconds, micros))
        }
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

/// A typed row value that implements opensrv-mysql's output encoder.
/// This avoids converting BLOBs to UTF-8 or hex text and emits the proper
/// MySQL binary representation for temporal values in prepared results.
#[derive(Debug, PartialEq)]
enum MysqlOutputValue {
    Bytes(Vec<u8>),
    Int(i64),
    UInt(u64),
    Float(f32),
    Double(f64),
    Date(u16, u8, u8, u8, u8, u8, u32),
    Time(bool, u32, u8, u8, u8, u32),
}

impl ToMysqlValue for MysqlOutputValue {
    fn to_mysql_text<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        match self {
            Self::Bytes(value) => value.to_mysql_text(writer),
            Self::Int(value) => value.to_mysql_text(writer),
            Self::UInt(value) => value.to_mysql_text(writer),
            Self::Float(value) => value.to_mysql_text(writer),
            Self::Double(value) => value.to_mysql_text(writer),
            Self::Date(y, m, d, h, min, sec, micros) => {
                let text = if *micros == 0 {
                    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{sec:02}")
                } else {
                    format!("{y:04}-{m:02}-{d:02} {h:02}:{min:02}:{sec:02}.{micros:06}")
                };
                writer.write_all(text.as_bytes())
            }
            Self::Time(negative, days, hours, minutes, seconds, micros) => {
                let total_hours = u64::from(*days) * 24 + u64::from(*hours);
                let sign = if *negative { "-" } else { "" };
                let text = if *micros == 0 {
                    format!("{sign}{total_hours:02}:{minutes:02}:{seconds:02}")
                } else {
                    format!("{sign}{total_hours:02}:{minutes:02}:{seconds:02}.{micros:06}")
                };
                writer.write_all(text.as_bytes())
            }
        }
    }

    fn to_mysql_bin<W: Write>(&self, writer: &mut W, column: &Column) -> io::Result<()> {
        match self {
            Self::Bytes(value) => value.to_mysql_bin(writer, column),
            Self::Int(value) => value.to_mysql_bin(writer, column),
            Self::UInt(value) => value.to_mysql_bin(writer, column),
            Self::Float(value) => value.to_mysql_bin(writer, column),
            Self::Double(value) => value.to_mysql_bin(writer, column),
            Self::Date(year, month, day, hour, minute, second, micros) => {
                match column.coltype {
                    ColumnType::MYSQL_TYPE_DATE | ColumnType::MYSQL_TYPE_NEWDATE => {
                        writer.write_all(&[4])?;
                        writer.write_all(&year.to_le_bytes())?;
                        writer.write_all(&[*month, *day])
                    }
                    ColumnType::MYSQL_TYPE_DATETIME | ColumnType::MYSQL_TYPE_TIMESTAMP
                    | ColumnType::MYSQL_TYPE_DATETIME2 | ColumnType::MYSQL_TYPE_TIMESTAMP2 => {
                        let len = if *micros != 0 { 11 } else if *hour != 0 || *minute != 0 || *second != 0 { 7 } else { 4 };
                        writer.write_all(&[len])?;
                        writer.write_all(&year.to_le_bytes())?;
                        writer.write_all(&[*month, *day])?;
                        if len >= 7 { writer.write_all(&[*hour, *minute, *second])?; }
                        if len == 11 { writer.write_all(&micros.to_le_bytes())?; }
                        Ok(())
                    }
                    _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "temporal value does not match result column type")),
                }
            }
            Self::Time(negative, days, hours, minutes, seconds, micros) => {
                if !matches!(column.coltype, ColumnType::MYSQL_TYPE_TIME | ColumnType::MYSQL_TYPE_TIME2) {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "time value does not match result column type"));
                }
                let len = if *days == 0 && *hours == 0 && *minutes == 0 && *seconds == 0 && *micros == 0 {
                    0
                } else if *micros == 0 { 8 } else { 12 };
                writer.write_all(&[len])?;
                if len == 0 { return Ok(()); }
                writer.write_all(&[u8::from(*negative)])?;
                writer.write_all(&days.to_le_bytes())?;
                writer.write_all(&[*hours, *minutes, *seconds])?;
                if len == 12 { writer.write_all(&micros.to_le_bytes())?; }
                Ok(())
            }
        }
    }
}

fn upstream_value_to_output(value: UpstreamValue) -> Option<MysqlOutputValue> {
    Some(match value {
        UpstreamValue::NULL => return None,
        UpstreamValue::Bytes(bytes) => MysqlOutputValue::Bytes(bytes),
        UpstreamValue::Int(value) => MysqlOutputValue::Int(value),
        UpstreamValue::UInt(value) => MysqlOutputValue::UInt(value),
        UpstreamValue::Float(value) => MysqlOutputValue::Float(value),
        UpstreamValue::Double(value) => MysqlOutputValue::Double(value),
        UpstreamValue::Date(year, month, day, hour, minute, second, micros) =>
            MysqlOutputValue::Date(year, month, day, hour, minute, second, micros),
        UpstreamValue::Time(negative, days, hours, minutes, seconds, micros) =>
            MysqlOutputValue::Time(negative, days, hours, minutes, seconds, micros),
    })
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
        colflags: ColumnFlags::from_bits_truncate(column.flags().bits()),
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
        let mut connection = match tokio::time::timeout(
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

        let statement = match tokio::time::timeout(std::time::Duration::from_secs(QUERY_TIMEOUT_SECS), session.connection.prep(query)).await.unwrap_or_else(|_| Err(mysql_async::DriverError::ConnectionClosed.into())) {
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

        let mut upstream_result = match tokio::time::timeout(std::time::Duration::from_secs(QUERY_TIMEOUT_SECS), session.connection.exec_iter(statement, values)).await.unwrap_or_else(|_| Err(mysql_async::DriverError::ConnectionClosed.into())) {
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

        while let Some(row_result) = match tokio::time::timeout(std::time::Duration::from_secs(QUERY_TIMEOUT_SECS), rows.next()).await { Ok(next) => next, Err(_) => return output.finish_error(ErrorKind::ER_UNKNOWN_ERROR, &b"upstream row stream timed out".to_vec()).await } {
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

            let values: Vec<Option<MysqlOutputValue>> = row
                .unwrap()
                .into_iter()
                .map(upstream_value_to_output)
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

        let mut upstream_result = match tokio::time::timeout(std::time::Duration::from_secs(QUERY_TIMEOUT_SECS), session.connection.query_iter(query)).await.unwrap_or_else(|_| Err(mysql_async::DriverError::ConnectionClosed.into())) {
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

        while let Some(row_result) = match tokio::time::timeout(std::time::Duration::from_secs(QUERY_TIMEOUT_SECS), rows.next()).await { Ok(next) => next, Err(_) => return output.finish_error(ErrorKind::ER_UNKNOWN_ERROR, &b"upstream row stream timed out".to_vec()).await } {
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

            let values: Vec<Option<MysqlOutputValue>> = row
                .unwrap()
                .into_iter()
                .map(upstream_value_to_output)
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
        assert_eq!(upstream_value_to_output(UpstreamValue::NULL), None);
    }

    #[test]
    fn preserves_signed_integer_values() {
        assert!(matches!(upstream_value_to_output(UpstreamValue::Int(-42)), Some(MysqlOutputValue::Int(-42))));
    }

    #[test]
    fn preserves_unsigned_integer_values() {
        assert!(matches!(upstream_value_to_output(UpstreamValue::UInt(42)), Some(MysqlOutputValue::UInt(42))));
    }

    #[test]
    fn preserves_binary_payloads_byte_for_byte() {
        let bytes = vec![0xff, 0x00, 0x80, 0x41];
        assert!(matches!(upstream_value_to_output(UpstreamValue::Bytes(bytes.clone())), Some(MysqlOutputValue::Bytes(value)) if value == bytes));
    }

    #[test]
    fn preserves_datetime_values_as_typed_values() {
        assert!(matches!(
            upstream_value_to_output(UpstreamValue::Date(2026, 11, 19, 12, 30, 45, 123456)),
            Some(MysqlOutputValue::Date(2026, 11, 19, 12, 30, 45, 123456))
        ));
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
    fn decodes_binary_date_parameter() {
        assert_eq!(decode_date_payload(&[0xe8, 0x07, 11, 19]), Ok((2024, 11, 19)));
    }

    #[test]
    fn decodes_binary_datetime_with_microseconds() {
        let bytes = [0xe8, 0x07, 11, 19, 12, 30, 45, 0x40, 0x0d, 0x03, 0x00];
        assert_eq!(decode_datetime_payload(&bytes), Ok((2024, 11, 19, 12, 30, 45, 200000)));
    }

    #[test]
    fn decodes_binary_time_with_days_and_microseconds() {
        let bytes = [1, 2, 0, 0, 0, 3, 4, 5, 0x40, 0x0d, 0x03, 0x00];
        assert_eq!(decode_time_payload(&bytes), Ok((true, 2, 3, 4, 5, 200000)));
    }

    #[test]
    fn rejects_invalid_binary_temporal_values() {
        assert!(decode_date_payload(&[0xe8, 0x07, 13, 19]).is_err());
        assert!(decode_datetime_payload(&[0; 5]).is_err());
        assert!(decode_time_payload(&[2, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn decodes_binary_date_parameter_into_upstream_value() {
        assert_eq!(
            convert_parameter(ValueInner::Date(&[0xe8, 0x07, 11, 19])),
            Ok(UpstreamValue::Date(2024, 11, 19, 0, 0, 0, 0))
        );
    }
}

