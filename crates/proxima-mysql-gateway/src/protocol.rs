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
pub const CLIENT_CONNECT_ATTRS: u32 = 0x0010_0000;
pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
pub const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
pub const CLIENT_SSL: u32 = 0x0000_0800;

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
            let second_len = auth_len.saturating_sub(8).max(13);
            let remaining = c.remaining();
            let take = second_len.min(remaining);
            if take > 0 {
                let part = c.take(take)?;
                let end = part.iter().position(|b| *b == 0).unwrap_or(part.len());
                auth.extend_from_slice(&part[..end]);
            }
        }
        let auth_plugin_name = if capability_flags & CLIENT_PLUGIN_AUTH != 0 && c.remaining() > 0 {
            Some(c.nul_string()?)
        } else {
            None
        };
        Ok(Self {
            protocol_version, server_version, connection_id, capability_flags,
            character_set, status_flags, auth_plugin_data: auth, auth_plugin_name,
        })
    }
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
            let length = c.lenenc_integer()?.ok_or(ProtocolError::InvalidLengthEncodedInteger)? as usize;
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
        let key_len = c.lenenc_integer()?.ok_or(ProtocolError::InvalidLengthEncodedInteger)? as usize;
        if key_len > 256 { return Err(ProtocolError::PacketTooLarge); }
        let key = c.utf8(c.take(key_len)?)?;
        let value_len = c.lenenc_integer()?.ok_or(ProtocolError::InvalidLengthEncodedInteger)? as usize;
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

#[cfg(test)]
mod tests {
    use super::*;

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
