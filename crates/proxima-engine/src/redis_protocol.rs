use sha2::{Digest, Sha256};
pub const MAX_FRAME_BYTES: usize = 1_048_576;
pub const MAX_ARGS: usize = 1024;
pub const MAX_BULK_BYTES: usize = 524_288;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespError { Malformed, LimitExceeded, UnsupportedCommand, InvalidTenant }

pub fn parse_command(input: &[u8]) -> Result<Option<(Vec<Vec<u8>>, usize)>, RespError> {
    if input.len() > MAX_FRAME_BYTES { return Err(RespError::LimitExceeded); }
    if input.is_empty() { return Ok(None); }
    if input[0] != b'*' { return Err(RespError::Malformed); }
    let (count, mut pos) = match decimal(input, 1)? { Some(v) => v, None => return Ok(None) };
    if count == 0 || count > MAX_ARGS { return Err(RespError::LimitExceeded); }
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        if pos >= input.len() { return Ok(None); }
        if input[pos] != b'$' { return Err(RespError::Malformed); }
        let (len, start) = match decimal(input, pos + 1)? { Some(v) => v, None => return Ok(None) };
        if len > MAX_BULK_BYTES { return Err(RespError::LimitExceeded); }
        let end = start.checked_add(len).ok_or(RespError::LimitExceeded)?;
        let next = end.checked_add(2).ok_or(RespError::LimitExceeded)?;
        if next > input.len() { return Ok(None); }
        if &input[end..next] != b"\r\n" { return Err(RespError::Malformed); }
        args.push(input[start..end].to_vec()); pos = next;
    }
    Ok(Some((args, pos)))
}
fn decimal(input: &[u8], start: usize) -> Result<Option<(usize, usize)>, RespError> {
    let Some(n) = input.get(start..).and_then(|s| s.windows(2).position(|w| w == b"\r\n")) else { return Ok(None) };
    let end = start + n; let digits = &input[start..end];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) { return Err(RespError::Malformed); }
    let value = std::str::from_utf8(digits).map_err(|_| RespError::Malformed)?.parse::<usize>().map_err(|_| RespError::LimitExceeded)?;
    Ok(Some((value, end + 2)))
}
pub fn tenant_prefix(tenant_id: &str) -> Result<Vec<u8>, RespError> {
    if tenant_id.trim().is_empty() || tenant_id.len() > 256 { return Err(RespError::InvalidTenant); }
    let digest = Sha256::digest(tenant_id.as_bytes());
    Ok(format!("proxima:{{{}}}:", hex::encode(&digest[..16])).into_bytes())
}
pub fn rewrite_keys(args: &mut [Vec<u8>], tenant_id: &str) -> Result<(), RespError> {
    if args.is_empty() { return Err(RespError::Malformed); }
    let cmd = std::str::from_utf8(&args[0]).map_err(|_| RespError::UnsupportedCommand)?.to_ascii_uppercase();
    let keys: Vec<usize> = match cmd.as_str() {
        "GET"|"SET"|"SETNX"|"GETSET"|"GETDEL"|"APPEND"|"STRLEN"|"INCR"|"DECR"|"INCRBY"|"DECRBY"|"EXPIRE"|"PEXPIRE"|"TTL"|"PTTL"|"PERSIST"|"TYPE"|"HGET"|"HSET"|"HSETNX"|"HMGET"|"HMSET"|"HDEL"|"HEXISTS"|"HLEN"|"HSTRLEN"|"HGETALL"|"LPUSH"|"RPUSH"|"LPOP"|"RPOP"|"LLEN"|"LRANGE"|"LINDEX"|"LSET"|"LREM"|"LTRIM"|"SADD"|"SREM"|"SISMEMBER"|"SMEMBERS"|"SCARD"|"SPOP"|"ZADD"|"ZREM"|"ZSCORE"|"ZRANGE"|"ZCARD"|"ZCOUNT"|"ZINCRBY"|"PFADD"|"GEOADD"|"XRANGE"|"XREVRANGE"|"XLEN"|"XADD"|"XDEL"|"XTRIM"|"XACK" => vec![1],
        "MGET"|"DEL"|"UNLINK"|"EXISTS"|"TOUCH" => (1..args.len()).collect(),
        "MSET"|"MSETNX" => { if args.len() < 3 || args.len() % 2 == 0 { return Err(RespError::Malformed); } (1..args.len()).step_by(2).collect() },
        "RENAME"|"RENAMENX"|"RPOPLPUSH"|"BRPOPLPUSH"|"SMOVE"|"COPY" => { if args.len() < 3 { return Err(RespError::Malformed); } vec![1,2] },
        "BITOP" => { if args.len() < 4 { return Err(RespError::Malformed); } (2..args.len()).collect() },
        _ => return Err(RespError::UnsupportedCommand),
    };
    let prefix = tenant_prefix(tenant_id)?;
    for i in keys { let key = args.get_mut(i).ok_or(RespError::Malformed)?; let mut v = prefix.clone(); v.extend_from_slice(key); *key = v; }
    Ok(())
}
pub fn encode_command(args: &[Vec<u8>]) -> Vec<u8> {
    let mut out = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args { out.extend_from_slice(b"$"); out.extend_from_slice(format!("{}\r\n", arg.len()).as_bytes()); out.extend_from_slice(arg); out.extend_from_slice(b"\r\n"); }
    out
}
#[cfg(test)]
mod tests {
    use super::*;
    fn frame(a: &[&[u8]]) -> Vec<u8> { encode_command(&a.iter().map(|v| v.to_vec()).collect::<Vec<_>>()) }
    #[test] fn parses_binary_and_pipeline() { let one=frame(&[b"SET",b"k",b"a\0b"]); let mut data=one.clone(); data.extend(frame(&[b"GET",b"k"])); let (a,n)=parse_command(&data).unwrap().unwrap(); assert_eq!(a[2],b"a\0b"); assert_eq!(n,one.len()); assert_eq!(parse_command(&data[n..]).unwrap().unwrap().0[0],b"GET"); }
    #[test] fn incomplete_is_not_a_command() { assert_eq!(parse_command(b"*2\r\n$3\r\nGET\r\n$4\r\nk"),Ok(None)); }
    #[test] fn tenant_prefix_is_opaque() { assert_ne!(tenant_prefix("a").unwrap(),tenant_prefix("b").unwrap()); assert_eq!(tenant_prefix("a").unwrap(),tenant_prefix("a").unwrap()); }
    #[test] fn mget_and_mset_namespace_keys_only() { let mut a=vec![b"MGET".to_vec(),b"a".to_vec(),b"b".to_vec()]; rewrite_keys(&mut a,"t").unwrap(); let p=tenant_prefix("t").unwrap(); assert!(a[1].starts_with(&p)&&a[2].starts_with(&p)); let mut b=vec![b"MSET".to_vec(),b"k".to_vec(),b"v".to_vec()]; rewrite_keys(&mut b,"t").unwrap(); assert!(b[1].starts_with(&p)); assert_eq!(b[2],b"v"); }
    #[test] fn bitop_rewrites_destination_and_sources_but_not_operation() { let mut a=vec![b"BITOP".to_vec(),b"AND".to_vec(),b"dest".to_vec(),b"left".to_vec(),b"right".to_vec()]; rewrite_keys(&mut a,"t").unwrap(); let p=tenant_prefix("t").unwrap(); assert_eq!(a[1],b"AND"); assert!(a[2].starts_with(&p)&&a[3].starts_with(&p)&&a[4].starts_with(&p)); }\n    #[test] fn rejects_empty_and_malformed_command_shapes() { for mut a in [vec![b"GET".to_vec()],vec![b"MSET".to_vec(),b"k".to_vec()],vec![b"BITOP".to_vec(),b"AND".to_vec(),b"d".to_vec()]] { assert_eq!(rewrite_keys(&mut a,"t"),Err(RespError::Malformed)); } }\n    #[test] fn dangerous_commands_are_denied() { for c in ["FLUSHALL","CONFIG","ACL","EVAL","SUBSCRIBE","PUBLISH","MONITOR","SELECT","MODULE"] { let mut a=vec![c.as_bytes().to_vec(),b"x".to_vec()]; assert_eq!(rewrite_keys(&mut a,"t"),Err(RespError::UnsupportedCommand)); } }
}
