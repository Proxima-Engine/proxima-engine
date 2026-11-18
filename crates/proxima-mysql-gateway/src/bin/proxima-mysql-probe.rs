use proxima_mysql_gateway::protocol::{
    validate_client_capabilities, Packet, ServerHandshake,
    CLIENT_CONNECT_ATTRS, CLIENT_DEPRECATE_EOF, CLIENT_LONG_FLAG, CLIENT_LONG_PASSWORD,
    CLIENT_MULTI_RESULTS, CLIENT_PLUGIN_AUTH, CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA,
    CLIENT_PROTOCOL_41, CLIENT_PS_MULTI_RESULTS, CLIENT_SECURE_CONNECTION, CLIENT_SESSION_TRACK,
    CLIENT_SSL, CLIENT_TRANSACTIONS, MAX_PACKET_PAYLOAD,
};
use rustls::{pki_types::ServerName, RootCertStore};
use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    fs::File,
    io::BufReader,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{client::TlsStream, TlsConnector};

type ProbeResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

const ASSERTION_ATTRIBUTE: &str = "_proxima_tenant_assertion";
const MAX_PACKET: usize = MAX_PACKET_PAYLOAD - 1;

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("MySQL gateway probe failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> ProbeResult<()> {
    let mut args = env::args().skip(1);
    let host = args.next().ok_or("missing gateway host")?;
    let port = args.next().ok_or("missing gateway port")?.parse::<u16>()?;
    let tls_name = args.next().ok_or("missing TLS server name")?;
    let ca_file = args.next().ok_or("missing CA file")?;
    let username = args.next().ok_or("missing gateway username")?;
    let password = args.next().ok_or("missing gateway password")?;
    let assertion = args.next().ok_or("missing tenant assertion")?;
    let other_database = args.next().ok_or("missing cross-tenant database name")?;
    let expect_denied = match args.next() {
        None => false,
        Some(flag) if flag == "--expect-auth-denied" => true,
        Some(_) => return Err("unknown probe option".into()),
    };

    let address: SocketAddr = format!("{host}:{port}").parse()?;
    let mut tcp = timeout(Duration::from_secs(5), TcpStream::connect(address)).await??;
    tcp.set_nodelay(true)?;

    let greeting = read_packet(&mut tcp).await?;
    if greeting.sequence != 0 {
        return Err("invalid server greeting sequence".into());
    }
    let server = ServerHandshake::parse(&greeting.payload)?;
    if server.auth_plugin_name.as_deref() != Some("caching_sha2_password")
        || server.auth_plugin_data.len() != 20
    {
        return Err("gateway advertised an unsupported authentication plugin".into());
    }
    let challenge: [u8; 20] = server.auth_plugin_data.as_slice().try_into()?;

    let flags = CLIENT_LONG_PASSWORD
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
    validate_client_capabilities(flags, server.capability_flags)?;

    let mut ssl_request = Vec::with_capacity(32);
    ssl_request.extend_from_slice(&flags.to_le_bytes());
    ssl_request.extend_from_slice(&(MAX_PACKET as u32).to_le_bytes());
    ssl_request.push(45);
    ssl_request.extend_from_slice(&[0u8; 23]);
    write_packet(&mut tcp, Packet { sequence: 1, payload: ssl_request }).await?;

    let mut roots = RootCertStore::empty();
    let ca_file = File::open(ca_file)?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(ca_file))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err("CA file contains no certificates".into());
    }
    for certificate in certs {
        roots.add(certificate)?;
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls_config));
    let server_name = ServerName::try_from(tls_name)?;
    let mut tls = timeout(
        Duration::from_secs(5),
        connector.connect(server_name, tcp),
    ).await??;

    let auth_response = caching_sha2_response(password.as_bytes(), &challenge);
    let mut response = Vec::with_capacity(256);
    response.extend_from_slice(&flags.to_le_bytes());
    response.extend_from_slice(&(MAX_PACKET as u32).to_le_bytes());
    response.push(45);
    response.extend_from_slice(&[0u8; 23]);
    response.extend_from_slice(username.as_bytes());
    response.push(0);
    push_lenenc(&mut response, auth_response.len());
    response.extend_from_slice(&auth_response);
    response.extend_from_slice(b"caching_sha2_password\0");

    let mut attributes = Vec::new();
    push_lenenc(&mut attributes, ASSERTION_ATTRIBUTE.len());
    attributes.extend_from_slice(ASSERTION_ATTRIBUTE.as_bytes());
    push_lenenc(&mut attributes, assertion.len());
    attributes.extend_from_slice(assertion.as_bytes());
    push_lenenc(&mut response, attributes.len());
    response.extend_from_slice(&attributes);
    write_packet(&mut tls, Packet { sequence: 2, payload: response }).await?;

    let auth = read_packet(&mut tls).await?;
    if auth.sequence != 3 {
        return Err("invalid gateway authentication packet sequence".into());
    }
    if auth.payload.first() == Some(&0xff) {
        if expect_denied {
            println!("[PASS] revoked gateway account is rejected");
            return Ok(());
        }
        return Err("gateway rejected the provisioned account or tenant assertion".into());
    }
    if auth.payload.as_slice() == [0x01, 0x03] {
        let ok = read_packet(&mut tls).await?;
        if ok.sequence != 4 || ok.payload.first() != Some(&0x00) {
            return Err("gateway did not complete caching_sha2_password authentication".into());
        }
    } else if auth.payload.first() != Some(&0x00) {
        return Err("unexpected gateway authentication response".into());
    }
    if expect_denied {
        return Err("revoked gateway account was unexpectedly accepted".into());
    }
    println!("[PASS] TLS, gateway authentication and signed tenant assertion");

    let ok = command(&mut tls, [vec![0x03], b"DO 1".to_vec()].concat()).await?;
    if ok.payload.first() != Some(&0x00) {
        return Err("tenant-scoped query did not return a MySQL OK packet".into());
    }
    println!("[PASS] tenant-bound MySQL command relay");

    let cross_tenant_sql = format!("SELECT * FROM {other_database}.records");
    let cross = command(&mut tls, [vec![0x03], cross_tenant_sql.into_bytes()].concat()).await?;
    if cross.payload.first() != Some(&0xff) {
        return Err("cross-tenant database query was not denied by MySQL grants".into());
    }
    println!("[PASS] cross-tenant database access denied");

    let mut switch_database = vec![0x02];
    switch_database.extend_from_slice(other_database.as_bytes());
    let switch = command(&mut tls, switch_database).await?;
    if switch.payload.first() != Some(&0xff) {
        return Err("COM_INIT_DB unexpectedly changed the tenant database".into());
    }
    println!("[PASS] client database switching rejected");

    let set_option = command(&mut tls, vec![0x1b, 0x00, 0x00]).await?;
    if set_option.payload.first() != Some(&0xff) {
        return Err("COM_SET_OPTION unexpectedly changed session protocol state".into());
    }
    println!("[PASS] client session-option changes rejected");

    let final_ok = command(&mut tls, [vec![0x03], b"DO 1".to_vec()].concat()).await?;
    if final_ok.payload.first() != Some(&0x00) {
        return Err("tenant session did not remain usable after rejected commands".into());
    }
    println!("[PASS] tenant session remains bound after rejected commands");
    Ok(())
}

async fn command(stream: &mut TlsStream<TcpStream>, payload: Vec<u8>) -> ProbeResult<Packet> {
    write_packet(stream, Packet { sequence: 0, payload }).await?;
    let response = read_packet(stream).await?;
    if response.sequence != 1 {
        return Err("invalid MySQL command response sequence".into());
    }
    Ok(response)
}

fn caching_sha2_response(password: &[u8], challenge: &[u8; 20]) -> Vec<u8> {
    let stage_one = Sha256::digest(password);
    let stage_two = Sha256::digest(stage_one);
    let mut material = Vec::with_capacity(52);
    material.extend_from_slice(&stage_two);
    material.extend_from_slice(challenge);
    let mask = Sha256::digest(material);
    stage_one.iter().zip(mask.iter()).map(|(left, right)| left ^ right).collect()
}

fn push_lenenc(output: &mut Vec<u8>, value: usize) {
    if value < 251 {
        output.push(value as u8);
    } else if value <= u16::MAX as usize {
        output.push(0xfc);
        output.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= 0x00ff_ffff {
        output.push(0xfd);
        output.push((value & 0xff) as u8);
        output.push(((value >> 8) & 0xff) as u8);
        output.push(((value >> 16) & 0xff) as u8);
    } else {
        output.push(0xfe);
        output.extend_from_slice(&(value as u64).to_le_bytes());
    }
}

async fn read_packet<S: AsyncRead + Unpin>(stream: &mut S) -> ProbeResult<Packet> {
    let mut header = [0u8; 4];
    timeout(Duration::from_secs(10), stream.read_exact(&mut header)).await??;
    let length = header[0] as usize
        | ((header[1] as usize) << 8)
        | ((header[2] as usize) << 16);
    if length > MAX_PACKET || length == MAX_PACKET_PAYLOAD {
        return Err("gateway packet exceeded probe bounds".into());
    }
    let mut payload = vec![0u8; length];
    timeout(Duration::from_secs(10), stream.read_exact(&mut payload)).await??;
    Ok(Packet { sequence: header[3], payload })
}

async fn write_packet<S: AsyncWrite + Unpin>(stream: &mut S, packet: Packet) -> ProbeResult<()> {
    let frame = packet.encode(MAX_PACKET)?;
    timeout(Duration::from_secs(10), stream.write_all(&frame)).await??;
    timeout(Duration::from_secs(10), stream.flush()).await??;
    Ok(())
}
