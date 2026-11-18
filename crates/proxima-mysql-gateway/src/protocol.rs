//! Bounded MySQL classic-protocol packet and handshake parsing.
//!
//! This module handles framing and the initial protocol handshake only. It does
//! not authenticate a user, route a tenant, or execute SQL. Callers must apply
//! tenant policy before opening any upstream connection.
use std::fmt;

pub const MAX_PACKET_PAYLOAD: usize = 0x00ff_ffff;
pub const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
pub const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
pub const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
pub const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
pub const CLIENT_SSL: u32 = 0x0000_0800;
pub const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Truncated,
    InvalidPacketLength,
    PacketTooLarge,
    UnexpectedSequence { expected: u8, actual: u8 },
    InvalidHandshake,
    UnsupportedCapabilities(u32),
    InvalidLengthEncodedInteger,
    InvalidUtf8,
    TrailingBytes,
    MultiPacketNotSupported,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "truncated MySQL protocol packet"),
            Self::InvalidPacketLength => write!(f, "invalid MySQL packet length"),
            Self::PacketTooLarge => write!(f, "MySQL packet exceeds configured maximum"),
            Self::UnexpectedSequence { expected, actual } => write!(f, "unexpected MySQL packet sequence: expected {expected}, received {actual}"),
            Self::InvalidHandshake => write!(f, "invalid MySQL handshake payload"),
            Self::UnsupportedCapabilities(flags) => write!(f, "unsupported MySQL client capability flags: 0x{flags:08x}"),
            Self::InvalidLengthEncodedInteger => write!(f, "invalid MySQL length-encoded integer"),
            Self::InvalidUtf8 => write!(f, "MySQL handshake contains invalid UTF-8"),
            Self::TrailingBytes => write!(f, "unexpected trailing bytes in MySQL handshake"),
            Self::MultiPacketNotSupported => write!(f, "multi-packet MySQL messages are not enabled in this protocol stage"),
        }
    }
}
impl std::error::Error for ProtocolError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub sequence: u8,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn decode(frame: &[u8], max_payload: usize) -> Result<Self, ProtocolError> {
        if frame.len() < 4 {
            return Err(ProtocolError::Truncated);
        }
        let length = frame[0] as usize
            | ((frame[1] as usize) << 8)
            | ((frame[2] as usize) << 16);
        if length > max_payload || length > MAX_PACKET_PAYLOAD {
            return Err(ProtocolError::PacketTooLarge);
        }
        if frame.len() != length + 4 {
            return Err(ProtocolError::InvalidPacketLength);
        }
        if length == MAX_PACKET_PAYLOAD {
            return Err(ProtocolError::MultiPacketNotSupported);
        }
        Ok(Self { sequence: frame[3], payload: frame[4..].to_vec() })
    }

    pub fn encode(&self, max_payload: usize) -> Result<Vec<u8>, ProtocolError> {
        let length = self.payload.len();
        if length > max_payload || length > MAX_PACKET_PAYLOAD {
            return Err(ProtocolError::PacketTooLarge);
        }
        if length == MAX_PACKET_PAYLOAD {
            return Err(ProtocolError::MultiPacketNotSupported);
        }
        let mut frame = Vec::with_capacity(length + 4);
        frame.push((length & 0xff) as u8);
        frame.push(((length >> 8) & 0xff) as u8);
        frame.push(((length >> 16) & 0xff) as u8);
        frame.push(self.sequence);
        frame.extend_from_slice(&self.payload);
        Ok(frame)
    }
}


pub fn validate_client_capabilities(client_flags: u32, server_flags: u32) -> Result<(), ProtocolError> {
    let unsupported = client_flags & !server_flags;
    if unsupported != 0 {
        return Err(ProtocolError::UnsupportedCapabilities(unsupported));
    }
    if client_flags & CLIENT_PROTOCOL_41 == 0 {
        return Err(ProtocolError::InvalidHandshake);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHandshake {
    pub protocol_version: u8,
    pub server_version: String,
    pub connection_id: u32,
    pub capability_flags: u32,
    pub character_set: u8,
    pub status_flags: u16,
    pub auth_plugin_data: Vec<u8>,
    pub auth_plugin_name: Option<String>,
}

impl ServerHandshake {
    pub fn parse(payload: &[u8]) -> Result<Self, ProtocolError> {
        let mut c = Cursor::new(payload);
        let protocol_version = c.u8()?;
        if protocol_version != 10 { return Err(ProtocolError::InvalidHandshake); }
        let server_version = c.nul_string()?;
        let connection_id = c.u32_le()?;
        let mut auth = c.take(8)?.to_vec();
        c.skip(1)?;
        let lower = c.u16_le()? as u32;
        let character_set = c.u8()?;
        let status_flags = c.u16_le()?;
        let upper = c.u16_le()? as u32;
        let capability_flags = lower | (upper << 16);
        let auth_len = c.u8()? as usize;
        c.skip(10)?;

        if capability_flags & CLIENT_PLUGIN_AUTH != 0 {
            if auth_len < 21 || c.remaining() < 13 {
                return Err(ProtocolError::InvalidHandshake);
            }
            let part = c.take(13)?;
            if part[12] != 0 {
                return Err(ProtocolError::InvalidHandshake);
            }
            auth.extend_from_slice(&part[..12]);
        }
        let auth_plugin_name = if capability_flags & CLIENT_PLUGIN_AUTH != 0 {
            let plugin = c.nul_string()?;
            if plugin.is_empty() { return Err(ProtocolError::InvalidHandshake); }
            Some(plugin)
        } else {
            None
        };
        Ok(Self {
            protocol_version, server_version, connection_id, capability_flags,
            character_set, status_flags, auth_plugin_data: auth, auth_plugin_name,
        })
    }
}


pub fn is_ssl_request(payload: &[u8]) -> Result<bool, ProtocolError> {
    if payload.len() != 32 { return Ok(false); }
    let mut c = Cursor::new(payload);
    let capabilities = c.u32_le()?;
    let _max_packet_size = c.u32_le()?;
    let _character_set = c.u8()?;
    c.skip(23)?;
    Ok(capabilities & CLIENT_SSL != 0 && capabilities & CLIENT_PROTOCOL_41 != 0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHandshake {
    pub capability_flags: u32,
    pub max_packet_size: u32,
    pub character_set: u8,
    pub username: String,
    pub auth_response: Vec<u8>,
    pub requested_database: Option<String>,
    pub auth_plugin_name: Option<String>,
    pub connection_attributes: Vec<(String, String)>,
}

impl ClientHandshake {
    pub fn parse(payload: &[u8], max_auth_bytes: usize, max_attributes_bytes: usize) -> Result<Self, ProtocolError> {
        let mut c = Cursor::new(payload);
        let capability_flags = c.u32_le()?;
        if capability_flags & CLIENT_PROTOCOL_41 == 0 {
            return Err(ProtocolError::InvalidHandshake);
        }
        let max_packet_size = c.u32_le()?;
        let character_set = c.u8()?;
        c.skip(23)?;
        let username = c.nul_string()?;
        if username.is_empty() || username.len() > 128 {
            return Err(ProtocolError::InvalidHandshake);
        }

        let auth_response = if capability_flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA != 0 {
            let length = usize::try_from(c.lenenc_integer()?.ok_or(ProtocolError::InvalidLengthEncodedInteger)?)
                .map_err(|_| ProtocolError::PacketTooLarge)?;
            if length > max_auth_bytes { return Err(ProtocolError::PacketTooLarge); }
            c.take(length)?.to_vec()
        } else if capability_flags & CLIENT_SECURE_CONNECTION != 0 {
            let length = c.u8()? as usize;
            if length > max_auth_bytes { return Err(ProtocolError::PacketTooLarge); }
            c.take(length)?.to_vec()
        } else {
            let value = c.nul_bytes()?;
            if value.len() > max_auth_bytes { return Err(ProtocolError::PacketTooLarge); }
            value.to_vec()
        };

        let requested_database = if capability_flags & CLIENT_CONNECT_WITH_DB != 0 {
            Some(c.nul_string()?)
        } else { None };
        let auth_plugin_name = if capability_flags & CLIENT_PLUGIN_AUTH != 0 && c.remaining() > 0 {
            Some(c.nul_string()?)
        } else { None };
        let connection_attributes = if capability_flags & CLIENT_CONNECT_ATTRS != 0 && c.remaining() > 0 {
            let length = c.lenenc_integer()?.ok_or(ProtocolError::InvalidLengthEncodedInteger)? as usize;
            if length > max_attributes_bytes { return Err(ProtocolError::PacketTooLarge); }
            parse_attributes(c.take(length)?)?
        } else { Vec::new() };

        if c.remaining() != 0 { return Err(ProtocolError::TrailingBytes); }
        Ok(Self { capability_flags, max_packet_size, character_set, username, auth_response,
            requested_database, auth_plugin_name, connection_attributes })
    }
}

pub fn verify_sequence(packet: &Packet, expected: u8) -> Result<(), ProtocolError> {
    if packet.sequence != expected {
        return Err(ProtocolError::UnexpectedSequence { expected, actual: packet.sequence });
    }
    Ok(())
}

fn parse_attributes(input: &[u8]) -> Result<Vec<(String, String)>, ProtocolError> {
    let mut c = Cursor::new(input);
    let mut attributes = Vec::new();
    while c.remaining() > 0 {
        if attributes.len() >= 64 { return Err(ProtocolError::PacketTooLarge); }
        let key_len = usize::try_from(c.lenenc_integer()?.ok_or(ProtocolError::InvalidLengthEncodedInteger)?)
            .map_err(|_| ProtocolError::PacketTooLarge)?;
        if key_len > 256 { return Err(ProtocolError::PacketTooLarge); }
        if key_len == 0 { return Err(ProtocolError::InvalidHandshake); }
        let key = c.utf8(c.take(key_len)?)?;
        let value_len = usize::try_from(c.lenenc_integer()?.ok_or(ProtocolError::InvalidLengthEncodedInteger)?)
            .map_err(|_| ProtocolError::PacketTooLarge)?;
        if value_len > 4096 { return Err(ProtocolError::PacketTooLarge); }
        let value = c.utf8(c.take(value_len)?)?;
        attributes.push((key, value));
    }
    Ok(attributes)
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn remaining(&self) -> usize { self.bytes.len().saturating_sub(self.offset) }
    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self.offset.checked_add(length).ok_or(ProtocolError::Truncated)?;
        if end > self.bytes.len() { return Err(ProtocolError::Truncated); }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }
    fn skip(&mut self, length: usize) -> Result<(), ProtocolError> { self.take(length).map(|_| ()) }
    fn u8(&mut self) -> Result<u8, ProtocolError> { Ok(self.take(1)?[0]) }
    fn u16_le(&mut self) -> Result<u16, ProtocolError> { let b = self.take(2)?; Ok(u16::from_le_bytes([b[0], b[1]])) }
    fn u32_le(&mut self) -> Result<u32, ProtocolError> { let b = self.take(4)?; Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]])) }
    fn nul_bytes(&mut self) -> Result<&'a [u8], ProtocolError> {
        let tail = &self.bytes[self.offset..];
        let end = tail.iter().position(|b| *b == 0).ok_or(ProtocolError::Truncated)?;
        self.offset += end + 1;
        Ok(&tail[..end])
    }
    fn nul_string(&mut self) -> Result<String, ProtocolError> {
        let bytes = self.nul_bytes()?;
        self.utf8(bytes)
    }
    fn utf8(&self, bytes: &[u8]) -> Result<String, ProtocolError> {
        std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| ProtocolError::InvalidUtf8)
    }
    fn lenenc_integer(&mut self) -> Result<Option<u64>, ProtocolError> {
        let first = self.u8()?;
        match first {
            0xfb => Ok(None),
            0xfc => { let b = self.take(2)?; Ok(Some(u16::from_le_bytes([b[0], b[1]]) as u64)) },
            0xfd => { let b = self.take(3)?; Ok(Some(b[0] as u64 | ((b[1] as u64) << 8) | ((b[2] as u64) << 16))) },
            0xfe => { let b = self.take(8)?; Ok(Some(u64::from_le_bytes(b.try_into().map_err(|_| ProtocolError::Truncated)?))) },
            0xff => Err(ProtocolError::InvalidLengthEncodedInteger),
            value => Ok(Some(value as u64)),
        }
    }
}



#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Quit = 0x01,
    InitDb = 0x02,
    Query = 0x03,
    FieldList = 0x04,
    Ping = 0x0e,
    ChangeUser = 0x11,
    StmtPrepare = 0x16,
    StmtExecute = 0x17,
    StmtSendLongData = 0x18,
    StmtClose = 0x19,
    StmtReset = 0x1a,
    SetOption = 0x1b,
    StmtFetch = 0x1c,
    ResetConnection = 0x1f,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    Empty,
    Unsupported(u8),
    ForbiddenTenantSwitch(Command),
}
impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty MySQL command payload"),
            Self::Unsupported(code) => write!(f, "unsupported MySQL command 0x{code:02x}"),
            Self::ForbiddenTenantSwitch(command) => write!(f, "MySQL command {command:?} may change database or authentication context and is forbidden"),
        }
    }
}
impl std::error::Error for CommandError {}

impl Command {
    pub fn parse(payload: &[u8]) -> Result<Self, CommandError> {
        let code = *payload.first().ok_or(CommandError::Empty)?;
        let command = match code {
            0x01 => Self::Quit,
            0x02 => Self::InitDb,
            0x03 => Self::Query,
            0x04 => Self::FieldList,
            0x0e => Self::Ping,
            0x11 => Self::ChangeUser,
            0x16 => Self::StmtPrepare,
            0x17 => Self::StmtExecute,
            0x18 => Self::StmtSendLongData,
            0x19 => Self::StmtClose,
            0x1a => Self::StmtReset,
            0x1b => Self::SetOption,
            0x1c => Self::StmtFetch,
            0x1f => Self::ResetConnection,
            other => return Err(CommandError::Unsupported(other)),
        };
        match command {
            Self::InitDb | Self::ChangeUser | Self::ResetConnection => {
                Err(CommandError::ForbiddenTenantSwitch(command))
            }
            other => Ok(other),
        }
    }
}

pub fn encode_server_handshake(
    connection_id: u32,
    challenge: &[u8; 20],
    server_version: &str,
    supports_tls: bool,
) -> Result<Vec<u8>, ProtocolError> {
    if server_version.is_empty() || server_version.len() > 128 || server_version.as_bytes().contains(&0) {
        return Err(ProtocolError::InvalidHandshake);
    }
    let mut capabilities = CLIENT_PROTOCOL_41
        | CLIENT_SECURE_CONNECTION
        | CLIENT_PLUGIN_AUTH
        | CLIENT_CONNECT_ATTRS
        | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;
    if supports_tls { capabilities |= CLIENT_SSL; }

    let mut payload = Vec::with_capacity(96);
    payload.push(10);
    payload.extend_from_slice(server_version.as_bytes());
    payload.push(0);
    payload.extend_from_slice(&connection_id.to_le_bytes());
    payload.extend_from_slice(&challenge[..8]);
    payload.push(0);
    payload.extend_from_slice(&(capabilities as u16).to_le_bytes());
    payload.push(45); // utf8mb4_general_ci
    payload.extend_from_slice(&2u16.to_le_bytes()); // SERVER_STATUS_AUTOCOMMIT
    payload.extend_from_slice(&((capabilities >> 16) as u16).to_le_bytes());
    payload.push(21); // 8-byte prefix + 12-byte suffix + NUL
    payload.extend_from_slice(&[0u8; 10]);
    payload.extend_from_slice(&challenge[8..]);
    payload.push(0);
    payload.extend_from_slice(b"caching_sha2_password\0");
    Packet { sequence: 0, payload }.encode(MAX_PACKET_PAYLOAD)
}

#[cfg(test)]
mod tests {
    use super::*;


    #[test]
    fn generated_server_greeting_parses_with_expected_auth_plugin_and_capabilities() {
        let challenge = [11u8; 20];
        let frame = encode_server_handshake(42, &challenge, "Proxima-MySQL-0.1", true).unwrap();
        let packet = Packet::decode(&frame, 4096).unwrap();
        let greeting = ServerHandshake::parse(&packet.payload).unwrap();
        assert_eq!(greeting.connection_id, 42);
        assert_eq!(greeting.auth_plugin_name.as_deref(), Some("caching_sha2_password"));
        assert_eq!(greeting.auth_plugin_data.len(), 20);
        assert!(greeting.capability_flags & CLIENT_SSL != 0);
    }

    #[test]
    fn tenant_switch_commands_are_rejected() {
        assert_eq!(Command::parse(&[0x02, b'd', b'b']), Err(CommandError::ForbiddenTenantSwitch(Command::InitDb)));
        assert_eq!(Command::parse(&[0x11]), Err(CommandError::ForbiddenTenantSwitch(Command::ChangeUser)));
        assert_eq!(Command::parse(&[0x1f]), Err(CommandError::ForbiddenTenantSwitch(Command::ResetConnection)));
        assert_eq!(Command::parse(&[0x03, b'S', b'E', b'L']), Ok(Command::Query));
    }


    #[test]
    fn detects_tls_upgrade_request_without_treating_it_as_full_authentication() {
        let flags = CLIENT_PROTOCOL_41 | CLIENT_SSL;
        let mut payload = Vec::new();
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&4096u32.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&[0u8; 23]);
        assert!(is_ssl_request(&payload).unwrap());
        assert_eq!(ClientHandshake::parse(&payload, 1024, 1024), Err(ProtocolError::Truncated));
    }


    #[test]
    fn client_cannot_negotiate_capabilities_the_gateway_did_not_advertise() {
        let server = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        let client = server | CLIENT_CONNECT_WITH_DB;
        assert_eq!(validate_client_capabilities(client, server), Err(ProtocolError::UnsupportedCapabilities(CLIENT_CONNECT_WITH_DB)));
    }

    #[test]
    fn packet_round_trip_and_sequence_validation() {
        let packet = Packet { sequence: 7, payload: b"hello".to_vec() };
        let frame = packet.encode(1024).unwrap();
        let decoded = Packet::decode(&frame, 1024).unwrap();
        assert_eq!(decoded, packet);
        verify_sequence(&decoded, 7).unwrap();
        assert_eq!(verify_sequence(&decoded, 1), Err(ProtocolError::UnexpectedSequence { expected: 1, actual: 7 }));
    }

    #[test]
    fn packet_decoder_rejects_truncation_and_oversize() {
        assert_eq!(Packet::decode(&[1, 0, 0], 1024), Err(ProtocolError::Truncated));
        assert_eq!(Packet::decode(&[5, 0, 0, 0, 1], 1024), Err(ProtocolError::InvalidPacketLength));
        assert_eq!(Packet::decode(&[2, 0, 0, 0, 1, 2], 1), Err(ProtocolError::PacketTooLarge));
    }

    #[test]
    fn client_handshake_rejects_legacy_protocol() {
        let mut payload = vec![0u8; 32];
        payload[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(ClientHandshake::parse(&payload, 1024, 1024), Err(ProtocolError::InvalidHandshake));
    }

    #[test]
    fn client_handshake_parses_username_and_secure_auth() {
        let flags = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH;
        let mut payload = Vec::new();
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&1024u32.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&[0u8; 23]);
        payload.extend_from_slice(b"tenant_a\0");
        payload.push(3);
        payload.extend_from_slice(&[1, 2, 3]);
        payload.extend_from_slice(b"caching_sha2_password\0");
        let parsed = ClientHandshake::parse(&payload, 1024, 1024).unwrap();
        assert_eq!(parsed.username, "tenant_a");
        assert_eq!(parsed.auth_response, vec![1, 2, 3]);
        assert_eq!(parsed.requested_database, None);
        assert_eq!(parsed.auth_plugin_name.as_deref(), Some("caching_sha2_password"));
    }

    #[test]
    fn client_database_selection_is_exposed_for_policy_rejection() {
        let flags = CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB;
        let mut payload = Vec::new();
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&1024u32.to_le_bytes());
        payload.push(45);
        payload.extend_from_slice(&[0u8; 23]);
        payload.extend_from_slice(b"tenant_a\0");
        payload.push(0);
        payload.extend_from_slice(b"other_tenant\0");
        let parsed = ClientHandshake::parse(&payload, 1024, 1024).unwrap();
        assert_eq!(parsed.requested_database.as_deref(), Some("other_tenant"));
    }
}
