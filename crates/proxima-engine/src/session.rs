use crate::protocol::{
    parse_backend_frame, parse_frontend_frame, parse_startup_packet, BackendMessage, StartupPacket,
    AUTHENTICATION_TAG, AUTH_OK, ERROR_RESPONSE_TAG, READY_FOR_QUERY_TAG,
};
use crate::tenant::{TenantContext, TenantTokenVerifier};
use crate::sql_guard;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub trait PgStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> PgStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
pub type BoxedPgStream = Box<dyn PgStream>;
use tracing::debug;

const MAX_STARTUP_PACKET: usize = 16 * 1024 * 1024;
const TENANT_TOKEN_PARAMETER: &str = "proxima_tenant_token";
const POSTGRES_IDENTIFIER_MAX_BYTES: usize = 63;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstablishedSession {
    pub tenant_context: Option<TenantContext>,
}

pub async fn establish(
    mut client: BoxedPgStream,
    mut upstream: BoxedPgStream,
    verifier: Option<&TenantTokenVerifier>,
    tenant_role_prefix: &str,
) -> io::Result<(BoxedPgStream, BoxedPgStream, EstablishedSession)> {
    let startup = read_startup(&mut client).await?;

    match startup {
        StartupPacket::Startup {
            protocol_version,
            parameters,
        } => {
            let (startup, tenant_context) =
                prepare_startup(protocol_version, parameters, verifier, tenant_role_prefix)?;
            debug!(
                tenant_bound = tenant_context.is_some(),
                "PostgreSQL startup packet received"
            );
            forward_startup(&mut upstream, &startup).await?;
            broker_startup_authentication(&mut client, &mut upstream).await?;
            Ok((client, upstream, EstablishedSession { tenant_context }))
        }
        StartupPacket::SslRequest => {
            upstream
                .write_all(&encode_startup(&StartupPacket::SslRequest)?)
                .await?;
            let mut response = [0u8; 1];
            upstream.read_exact(&mut response).await?;
            client.write_all(&response).await?;

            if response[0] == b'S' {
                if verifier.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "Proxima tenant enforcement cannot run through end-to-end TLS without TLS termination",
                    ));
                }
                return Ok((
                    client,
                    upstream,
                    EstablishedSession {
                        tenant_context: None,
                    },
                ));
            }

            let startup = read_startup(&mut client).await?;
            match startup {
                StartupPacket::Startup {
                    protocol_version,
                    parameters,
                } => {
                    let (startup, tenant_context) = prepare_startup(
                        protocol_version,
                        parameters,
                        verifier,
                        tenant_role_prefix,
                    )?;
                    forward_startup(&mut upstream, &startup).await?;
                    broker_startup_authentication(&mut client, &mut upstream).await?;
                    Ok((client, upstream, EstablishedSession { tenant_context }))
                }
                other => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected PostgreSQL startup after SSL rejection, got {other:?}"),
                )),
            }
        }
        StartupPacket::CancelRequest {
            process_id,
            secret_key,
        } => {
            forward_startup(
                &mut upstream,
                &StartupPacket::CancelRequest {
                    process_id,
                    secret_key,
                },
            )
            .await?;
            Ok((
                client,
                upstream,
                EstablishedSession {
                    tenant_context: None,
                },
            ))
        }
        StartupPacket::Unknown { .. } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported PostgreSQL startup packet",
        )),
    }
}

fn prepare_startup(
    protocol_version: i32,
    parameters: Vec<(String, String)>,
    verifier: Option<&TenantTokenVerifier>,
    tenant_role_prefix: &str,
) -> io::Result<(StartupPacket, Option<TenantContext>)> {
    let mut tenant_token = None;
    let mut forwarded = Vec::with_capacity(parameters.len());

    for (key, value) in parameters {
        if key == TENANT_TOKEN_PARAMETER {
            if tenant_token.replace(value).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Proxima tenant token",
                ));
            }
        } else if key == "options" {
            let (clean_options, option_token) = extract_tenant_token_from_options(&value)?;
            if let Some(option_token) = option_token {
                if tenant_token.replace(option_token).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "duplicate Proxima tenant token",
                    ));
                }
            }
            if !clean_options.is_empty() {
                forwarded.push((key, clean_options));
            }
        } else {
            forwarded.push((key, value));
        }
    }

    let tenant_context = match verifier {
        Some(verifier) => {
            let token = tenant_token.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Proxima tenant token is required",
                )
            })?;

            Some(verifier.verify_now(&token).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("invalid Proxima tenant token: {error}"),
                )
            })?)
        }
        None => None,
    };

    if tenant_context.is_some() {
        for (key, value) in &forwarded {
            let key = key.to_ascii_lowercase();
            let value = value.trim().to_ascii_lowercase();
            let blocked = key == "role"
                || key == "session_authorization"
                || key == "row_security" && ["off","false","0","no"].contains(&value.as_str())
                || key == "session_replication_role" && value == "replica"
                || key == "options" && sql_guard::blocks_tenant_startup_options(value.as_str());
            if blocked {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "tenant-bound PostgreSQL startup options cannot change roles or disable row security",
                ));
            }
        }
    }

    if let Some(context) = tenant_context.as_ref() {
        let normalized_tenant_id = context.tenant_id.replace('-', "_");
        let role = format!("{tenant_role_prefix}{normalized_tenant_id}");
        if role.len() > POSTGRES_IDENTIFIER_MAX_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tenant role name exceeds PostgreSQL identifier limit",
            ));
        }
        forwarded.retain(|(key, _)| key != "user");
        forwarded.push(("user".to_owned(), role));
    }

    Ok((
        StartupPacket::Startup {
            protocol_version,
            parameters: forwarded,
        },
        tenant_context,
    ))
}

fn extract_tenant_token_from_options(value: &str) -> io::Result<(String, Option<String>)> {
    let mut tokens = value.split_whitespace().peekable();
    let mut output = Vec::new();
    let mut tenant_token = None;

    while let Some(token) = tokens.next() {
        if token == "-c" {
            let assignment = tokens.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "options contains incomplete -c")
            })?;
            if let Some(token_value) = assignment.strip_prefix("proxima_tenant_token=") {
                if token_value.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Proxima tenant token in options is empty",
                    ));
                }
                if tenant_token.replace(token_value.to_owned()).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "duplicate Proxima tenant token",
                    ));
                }
                continue;
            }
            output.push("-c".to_owned());
            output.push(assignment.to_owned());
        } else if let Some(token_value) = token.strip_prefix("proxima_tenant_token=") {
            if token_value.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Proxima tenant token in options is empty",
                ));
            }
            if tenant_token.replace(token_value.to_owned()).is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "duplicate Proxima tenant token",
                ));
            }
        } else {
            output.push(token.to_owned());
        }
    }

    Ok((output.join(" "), tenant_token))
}

async fn broker_startup_authentication(
    client: &mut dyn PgStream,
    upstream: &mut dyn PgStream,
) -> io::Result<()> {
    let mut authenticated = false;

    loop {
        let frame = read_backend_frame(upstream).await?;
        client.write_all(&frame).await?;

        let message = parse_backend_frame(&frame)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete backend frame")
            })?
            .0;

        if message.tag == ERROR_RESPONSE_TAG {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PostgreSQL authentication/startup failed",
            ));
        }

        if message.tag == AUTHENTICATION_TAG {
            let auth_code = parse_authentication_code(&message)?;
            match auth_code {
                AUTH_OK => authenticated = true,
                3 | 5 | 7 | 8 | 9 | 10 | 11 => {
                    let response = read_frontend_frame(client).await?;
                    upstream.write_all(&response).await?;
                }
                12 => {}
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("unsupported PostgreSQL authentication method: {other}"),
                    ));
                }
            }
        }

        if message.tag == READY_FOR_QUERY_TAG {
            if !authenticated {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "PostgreSQL session became ready without AuthenticationOk",
                ));
            }
            return Ok(());
        }
    }
}

fn parse_authentication_code(message: &BackendMessage) -> io::Result<i32> {
    if message.payload.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated PostgreSQL authentication message",
        ));
    }
    Ok(i32::from_be_bytes(message.payload[..4].try_into().unwrap()))
}

async fn read_backend_frame(stream: &mut dyn PgStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let length = i32::from_be_bytes(header[1..5].try_into().unwrap());
    if !(4..=MAX_STARTUP_PACKET as i32).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid PostgreSQL backend frame length: {length}"),
        ));
    }
    let mut frame = vec![0u8; 5 + length as usize - 4];
    frame[..5].copy_from_slice(&header);
    stream.read_exact(&mut frame[5..]).await?;
    Ok(frame)
}

async fn read_frontend_frame(stream: &mut dyn PgStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let length = i32::from_be_bytes(header[1..5].try_into().unwrap());
    if !(4..=MAX_STARTUP_PACKET as i32).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid PostgreSQL frontend frame length: {length}"),
        ));
    }
    let mut frame = vec![0u8; 5 + length as usize - 4];
    frame[..5].copy_from_slice(&header);
    stream.read_exact(&mut frame[5..]).await?;
    parse_frontend_frame(&frame)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete frontend frame"))?;
    Ok(frame)
}

async fn read_startup(stream: &mut dyn PgStream) -> io::Result<StartupPacket> {
    let mut length_bytes = [0u8; 4];
    stream.read_exact(&mut length_bytes).await?;

    let length = u32::from_be_bytes(length_bytes) as usize;
    if !(8..=MAX_STARTUP_PACKET).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid PostgreSQL startup length: {length}"),
        ));
    }

    let mut packet = vec![0u8; length];
    packet[..4].copy_from_slice(&length_bytes);
    stream.read_exact(&mut packet[4..]).await?;

    parse_startup_packet(&packet)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
        .map(|(startup, _)| startup)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete startup packet"))
}

async fn forward_startup(stream: &mut dyn PgStream, startup: &StartupPacket) -> io::Result<()> {
    stream.write_all(&encode_startup(startup)?).await
}

fn encode_startup(startup: &StartupPacket) -> io::Result<Vec<u8>> {
    match startup {
        StartupPacket::SslRequest => Ok(8i32
            .to_be_bytes()
            .into_iter()
            .chain(crate::protocol::SSL_REQUEST_CODE.to_be_bytes())
            .collect()),
        StartupPacket::CancelRequest {
            process_id,
            secret_key,
        } => {
            let mut packet = Vec::with_capacity(16);
            packet.extend_from_slice(&16i32.to_be_bytes());
            packet.extend_from_slice(&crate::protocol::CANCEL_REQUEST_CODE.to_be_bytes());
            packet.extend_from_slice(&process_id.to_be_bytes());
            packet.extend_from_slice(&secret_key.to_be_bytes());
            Ok(packet)
        }
        StartupPacket::Startup {
            protocol_version,
            parameters,
        } => {
            let mut body = Vec::new();
            body.extend_from_slice(&protocol_version.to_be_bytes());

            for (key, value) in parameters {
                body.extend_from_slice(key.as_bytes());
                body.push(0);
                body.extend_from_slice(value.as_bytes());
                body.push(0);
            }
            body.push(0);

            let length = body.len() + 4;
            let length = i32::try_from(length).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "startup packet too large")
            })?;

            let mut packet = Vec::with_capacity(length as usize);
            packet.extend_from_slice(&length.to_be_bytes());
            packet.extend_from_slice(&body);
            Ok(packet)
        }
        StartupPacket::Unknown { .. } => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "cannot encode unknown startup packet",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::TenantTokenVerifier;

    fn verifier() -> TenantTokenVerifier {
        TenantTokenVerifier::new(b"01234567890123456789012345678901").unwrap()
    }

    #[test]
    fn extracts_and_removes_tenant_token() {
        let verifier = verifier();
        let token = verifier.sign_for_test("tenant_a", u64::MAX);
        let (startup, context) = prepare_startup(
            crate::protocol::PROTOCOL_3_0,
            vec![
                ("user".into(), "proxima".into()),
                (TENANT_TOKEN_PARAMETER.into(), token),
            ],
            Some(&verifier),
            "proxima_tenant_",
        )
        .unwrap();

        assert_eq!(context.unwrap().tenant_id, "tenant_a");
        assert_eq!(
            startup,
            StartupPacket::Startup {
                protocol_version: crate::protocol::PROTOCOL_3_0,
                parameters: vec![("user".into(), "proxima_tenant_tenant_a".into())],
            }
        );
    }

    #[test]
    fn normalizes_hyphens_in_uuid_tenant_role() {
        let verifier = verifier();
        let tenant_id = "caeaad20-744b-4f3b-9f5d-feb95c051141";
        let token = verifier.sign_for_test(tenant_id, u64::MAX);
        let (startup, _) = prepare_startup(
            crate::protocol::PROTOCOL_3_0,
            vec![
                ("user".into(), "proxima".into()),
                (TENANT_TOKEN_PARAMETER.into(), token),
            ],
            Some(&verifier),
            "proxima_tenant_",
        )
        .unwrap();

        assert_eq!(
            startup,
            StartupPacket::Startup {
                protocol_version: crate::protocol::PROTOCOL_3_0,
                parameters: vec![(
                    "user".into(),
                    "proxima_tenant_caeaad20_744b_4f3b_9f5d_feb95c051141".into()
                )],
            }
        );
    }

    #[test]
    fn rejects_missing_token_when_enforcement_is_enabled() {
        let verifier = verifier();
        let error = prepare_startup(
            crate::protocol::PROTOCOL_3_0,
            vec![("user".into(), "proxima".into())],
            Some(&verifier),
            "proxima_tenant_",
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn extracts_token_from_libpq_options() {
        let verifier = verifier();
        let token = verifier.sign_for_test("tenant_a", u64::MAX);
        let (options, extracted) = extract_tenant_token_from_options(&format!(
            "-c proxima_tenant_token={token} -c statement_timeout=1000"
        ))
        .unwrap();

        assert_eq!(extracted, Some(token));
        assert_eq!(options, "-c statement_timeout=1000");
    }

    #[test]
    fn rejects_duplicate_option_tokens() {
        let verifier = verifier();
        let token = verifier.sign_for_test("tenant_a", u64::MAX);
        let error = extract_tenant_token_from_options(&format!(
            "-c proxima_tenant_token={token} proxima_tenant_token={token}"
        ))
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_role_names_over_postgres_limit() {
        let verifier = verifier();
        let token = verifier.sign_for_test("tenant_a", u64::MAX);
        let error = prepare_startup(
            crate::protocol::PROTOCOL_3_0,
            vec![(TENANT_TOKEN_PARAMETER.into(), token)],
            Some(&verifier),
            &"x".repeat(63),
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn rejects_invalid_tenant_signature() {
        let verifier = verifier();
        let mut token = verifier.sign_for_test("tenant_a", u64::MAX);
        let last = token.pop().unwrap();
        token.push(if last == 'a' { 'b' } else { 'a' });
        let error = prepare_startup(
            crate::protocol::PROTOCOL_3_0,
            vec![(TENANT_TOKEN_PARAMETER.into(), token)],
            Some(&verifier),
            "proxima_tenant_",
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn tenant_switch_between_connections_maps_to_distinct_roles() {
        let verifier = verifier();
        for (tenant, role) in [
            ("tenant_a", "proxima_tenant_tenant_a"),
            ("tenant_b", "proxima_tenant_tenant_b"),
            ("tenant_a", "proxima_tenant_tenant_a"),
        ] {
            let token = verifier.sign_for_test(tenant, u64::MAX);
            let (startup, context) = prepare_startup(
                crate::protocol::PROTOCOL_3_0,
                vec![
                    ("user".into(), "proxima".into()),
                    (TENANT_TOKEN_PARAMETER.into(), token),
                ],
                Some(&verifier),
                "proxima_tenant_",
            )
            .unwrap();
            assert_eq!(context.unwrap().tenant_id, tenant);
            assert_eq!(
                startup,
                StartupPacket::Startup {
                    protocol_version: crate::protocol::PROTOCOL_3_0,
                    parameters: vec![("user".into(), role.into())],
                }
            );
        }
    }

    #[test]
    fn rejects_duplicate_tokens() {
        let verifier = verifier();
        let token = verifier.sign_for_test("tenant_a", u64::MAX);
        let error = prepare_startup(
            crate::protocol::PROTOCOL_3_0,
            vec![
                (TENANT_TOKEN_PARAMETER.into(), token.clone()),
                (TENANT_TOKEN_PARAMETER.into(), token),
            ],
            Some(&verifier),
            "proxima_tenant_",
        )
        .unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
