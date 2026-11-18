use proxima_mysql_gateway::protocol::{
    Packet, ServerHandshake, CLIENT_CONNECT_ATTRS, CLIENT_DEPRECATE_EOF,
    CLIENT_LONG_FLAG, CLIENT_LONG_PASSWORD, CLIENT_MULTI_RESULTS,
    CLIENT_PLUGIN_AUTH, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
    CLIENT_PROTOCOL_41, CLIENT_PS_MULTI_RESULTS, CLIENT_SECURE_CONNECTION,
    CLIENT_SESSION_TRACK, CLIENT_SSL, CLIENT_TRANSACTIONS,
};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use sha2::{Digest, Sha256};
use std::{env, fs::File, io::BufReader, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

const MAX_PACKET: usize = 16_777_214;

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing required test environment variable {name}"))
}

fn lenenc_integer(value: usize, out: &mut Vec<u8>) {
    if value < 251 {
        out.push(value as u8);
    } else if value <= 0xffff {
        out.push(0xfc);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0xff_ffff {
        out.push(0xfd);
        out.push((value & 0xff) as u8);
        out.push(((value >> 8) & 0xff) as u8);
        out.push(((value >> 16) & 0xff) as u8);
    } else {
        out.push(0xfe);
        out.extend_from_slice(&(value as u64).to_le_bytes());
    }
}

fn lenenc_bytes(value: &[u8], out: &mut Vec<u8>) {
    lenenc_integer(value.len(), out);
    out.extend_from_slice(value);
}

fn caching_sha2_response(password: &str, challenge: &[u8]) -> Vec<u8> {
    let stage_one = Sha256::digest(password.as_bytes());
    let stage_two = Sha256::digest(stage_one);
    let mut material = Vec::with_capacity(stage_two.len() + challenge.len());
    material.extend_from_slice(&stage_two);
    material.extend_from_slice(challenge);
    let mask = Sha256::digest(material);
    stage_one.iter().zip(mask.iter()).map(|(a, b)| a ^ b).collect()
}

async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Packet, String> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.map_err(|e| e.to_string())?;
    let length = header[0] as usize
        | ((header[1] as usize) << 8)
        | ((header[2] as usize) << 16);
    if length > MAX_PACKET || length >= 0x00ff_ffff {
        return Err("gateway returned an oversized MySQL packet".into());
    }
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload).await.map_err(|e| e.to_string())?;
    Ok(Packet { sequence: header[3], payload })
}

async fn write_packet<S: AsyncWrite + Unpin>(
    stream: &mut S,
    packet: &Packet,
) -> Result<(), String> {
    let frame = packet.encode(MAX_PACKET).map_err(|e| e.to_string())?;
    stream.write_all(&frame).await.map_err(|e| e.to_string())?;
    stream.flush().await.map_err(|e| e.to_string())
}

fn tls_connector(ca_file: &str) -> Result<TlsConnector, String> {
    let file = File::open(ca_file).map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(file);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots.add(certificate).map_err(|e| e.to_string())?;
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

async fn connect_gateway(
    address: SocketAddr,
    connector: &TlsConnector,
    username: &str,
    password: &str,
    assertion: &str,
) -> Result<TlsStream<TcpStream>, String> {
    let mut tcp = TcpStream::connect(address).await.map_err(|e| e.to_string())?;
    let greeting_packet = read_packet(&mut tcp).await?;
    if greeting_packet.sequence != 0 {
        return Err("gateway greeting sequence was not zero".into());
    }
    let greeting = ServerHandshake::parse(&greeting_packet.payload)
        .map_err(|e| e.to_string())?;
    if greeting.auth_plugin_name.as_deref() != Some("caching_sha2_password")
        || greeting.auth_plugin_data.len() != 20
    {
        return Err("gateway did not offer the supported caching_sha2_password plugin".into());
    }

    let capabilities = CLIENT_LONG_PASSWORD
        | CLIENT_LONG_FLAG
        | CLIENT_PROTOCOL_41
        | CLIENT_SSL
        | CLIENT_TRANSACTIONS
        | CLIENT_SECURE_CONNECTION
        | CLIENT_MULTI_RESULTS
        | CLIENT_PS_MULTI_RESULTS
        | CLIENT_PLUGIN_AUTH
        | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
        | CLIENT_CONNECT_ATTRS
        | CLIENT_SESSION_TRACK
        | CLIENT_DEPRECATE_EOF;

    let mut ssl_request = Vec::with_capacity(32);
    ssl_request.extend_from_slice(&capabilities.to_le_bytes());
    ssl_request.extend_from_slice(&(MAX_PACKET as u32).to_le_bytes());
    ssl_request.push(45);
    ssl_request.extend_from_slice(&[0u8; 23]);
    write_packet(
        &mut tcp,
        &Packet { sequence: 1, payload: ssl_request },
    ).await?;

    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|e| e.to_string())?;
    let mut tls = connector.connect(server_name, tcp)
        .await
        .map_err(|e| e.to_string())?;

    let auth = caching_sha2_response(password, &greeting.auth_plugin_data);
    let mut response = Vec::with_capacity(512);
    response.extend_from_slice(&capabilities.to_le_bytes());
    response.extend_from_slice(&(MAX_PACKET as u32).to_le_bytes());
    response.push(45);
    response.extend_from_slice(&[0u8; 23]);
    response.extend_from_slice(username.as_bytes());
    response.push(0);
    lenenc_bytes(&auth, &mut response);
    response.extend_from_slice(b"caching_sha2_password\0");

    let mut attributes = Vec::new();
    lenenc_bytes(b"_proxima_tenant_assertion", &mut attributes);
    lenenc_bytes(assertion.as_bytes(), &mut attributes);
    lenenc_integer(attributes.len(), &mut response);
    response.extend_from_slice(&attributes);

    write_packet(
        &mut tls,
        &Packet { sequence: 2, payload: response },
    ).await?;

    let fast_auth = read_packet(&mut tls).await?;
    if fast_auth.sequence != 3 || fast_auth.payload.as_slice() != [0x01, 0x03] {
        return Err(if fast_auth.payload.first() == Some(&0xff) {
            "gateway rejected the account or tenant assertion".into()
        } else {
            "gateway returned an invalid fast-auth packet".into()
        });
    }
    let ok = read_packet(&mut tls).await?;
    if ok.sequence != 4 || ok.payload.first() != Some(&0x00) {
        return Err("gateway did not complete the MySQL authentication handshake".into());
    }
    Ok(tls)
}

async fn command(
    stream: &mut TlsStream<TcpStream>,
    payload: Vec<u8>,
) -> Result<Packet, String> {
    write_packet(stream, &Packet { sequence: 0, payload }).await?;
    let response = read_packet(stream).await?;
    if response.sequence != 1 {
        return Err(format!("unexpected response sequence {}", response.sequence));
    }
    Ok(response)
}

async fn query(
    stream: &mut TlsStream<TcpStream>,
    sql: &str,
) -> Result<Packet, String> {
    let mut payload = Vec::with_capacity(sql.len() + 1);
    payload.push(0x03); // COM_QUERY
    payload.extend_from_slice(sql.as_bytes());
    command(stream, payload).await
}

fn assert_ok(response: &Packet, label: &str) {
    assert_ne!(
        response.payload.first(),
        Some(&0xff),
        "{label}: MySQL server rejected the command: {:?}",
        String::from_utf8_lossy(&response.payload)
    );
}

fn assert_denied(response: &Packet, label: &str) {
    assert_eq!(
        response.payload.first(),
        Some(&0xff),
        "{label}: expected MySQL ERR packet, received {:?}",
        response.payload
    );
}

#[tokio::test]
#[ignore = "requires disposable MySQL 8.4 and a running Proxima MySQL gateway"]
async fn gateway_enforces_tenant_database_and_session_boundaries() {
    let address: SocketAddr = required("PROXIMA_MYSQL_TEST_GATEWAY_ADDR").parse().unwrap();
    let connector = tls_connector(&required("PROXIMA_MYSQL_TEST_CA_FILE")).unwrap();
    let user_a = required("PROXIMA_MYSQL_TEST_USER_A");
    let password_a = required("PROXIMA_MYSQL_TEST_PASSWORD_A");
    let assertion_a = required("PROXIMA_MYSQL_TEST_ASSERTION_A");
    let user_b = required("PROXIMA_MYSQL_TEST_USER_B");
    let password_b = required("PROXIMA_MYSQL_TEST_PASSWORD_B");
    let assertion_b = required("PROXIMA_MYSQL_TEST_ASSERTION_B");
    let database_a = required("PROXIMA_MYSQL_TEST_DATABASE_A");
    let database_b = required("PROXIMA_MYSQL_TEST_DATABASE_B");

    let mut tenant_a = connect_gateway(address, &connector, &user_a, &password_a, &assertion_a)
        .await.expect("Tenant A gateway authentication should succeed");
    let own_query = query(&mut tenant_a, &format!("SELECT secret FROM {database_a}.gateway_probe")).await.unwrap();
    assert_ok(&own_query, "Tenant A own-database SELECT");
    drop(tenant_a);

    let mut tenant_a_cross_read = connect_gateway(address, &connector, &user_a, &password_a, &assertion_a)
        .await.unwrap();
    let cross_read = query(&mut tenant_a_cross_read, &format!("SELECT secret FROM {database_b}.gateway_probe")).await.unwrap();
    assert_denied(&cross_read, "Tenant A cross-tenant SELECT");
    drop(tenant_a_cross_read);

    let mut tenant_a_cross_write = connect_gateway(address, &connector, &user_a, &password_a, &assertion_a)
        .await.unwrap();
    let cross_write = query(&mut tenant_a_cross_write, &format!("INSERT INTO {database_b}.gateway_probe VALUES (2, 'forbidden')")).await.unwrap();
    assert_denied(&cross_write, "Tenant A cross-tenant INSERT");
    drop(tenant_a_cross_write);

    let mut tenant_a_use = connect_gateway(address, &connector, &user_a, &password_a, &assertion_a)
        .await.unwrap();
    let use_other = query(&mut tenant_a_use, &format!("USE {database_b}")).await.unwrap();
    assert_denied(&use_other, "Tenant A SQL USE");
    drop(tenant_a_use);

    let mut tenant_a_init_db = connect_gateway(address, &connector, &user_a, &password_a, &assertion_a)
        .await.unwrap();
    let mut init_db = vec![0x02];
    init_db.extend_from_slice(database_b.as_bytes());
    let init_db_result = command(&mut tenant_a_init_db, init_db).await.unwrap();
    assert_denied(&init_db_result, "COM_INIT_DB");
    drop(tenant_a_init_db);

    let mut tenant_a_set_option = connect_gateway(address, &connector, &user_a, &password_a, &assertion_a)
        .await.unwrap();
    let set_option = command(&mut tenant_a_set_option, vec![0x1b, 0x00, 0x00]).await.unwrap();
    assert_denied(&set_option, "COM_SET_OPTION");
    drop(tenant_a_set_option);

    let mut tenant_b = connect_gateway(address, &connector, &user_b, &password_b, &assertion_b)
        .await.expect("Tenant B gateway authentication should succeed");
    let own_b = query(&mut tenant_b, &format!("SELECT secret FROM {database_b}.gateway_probe")).await.unwrap();
    assert_ok(&own_b, "Tenant B own-database SELECT");
    drop(tenant_b);

    let mut tenant_b_cross_read = connect_gateway(address, &connector, &user_b, &password_b, &assertion_b)
        .await.unwrap();
    let cross_read_b = query(&mut tenant_b_cross_read, &format!("SELECT secret FROM {database_a}.gateway_probe")).await.unwrap();
    assert_denied(&cross_read_b, "Tenant B cross-tenant SELECT");
}

#[tokio::test]
#[ignore = "requires a tenant revoked from the running gateway registry"]
async fn revoked_gateway_account_cannot_open_a_new_session() {
    let address: SocketAddr = required("PROXIMA_MYSQL_TEST_GATEWAY_ADDR").parse().unwrap();
    let connector = tls_connector(&required("PROXIMA_MYSQL_TEST_CA_FILE")).unwrap();
    let result = connect_gateway(
        address,
        &connector,
        &required("PROXIMA_MYSQL_TEST_REVOKED_USER"),
        &required("PROXIMA_MYSQL_TEST_REVOKED_PASSWORD"),
        &required("PROXIMA_MYSQL_TEST_REVOKED_ASSERTION"),
    ).await;
    assert!(result.is_err(), "revoked gateway account unexpectedly authenticated");
}
