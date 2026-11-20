use crate::redis_protocol::{encode_command, parse_command, rewrite_keys, MAX_FRAME_BYTES};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs::File, future::Future, io::{self, BufReader}, net::SocketAddr, path::Path, pin::Pin, sync::Arc, time::Duration};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::Semaphore, time::timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};

trait RedisIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RedisIo for T {}
type Io = Box<dyn RedisIo>;

#[derive(Clone)]
struct Principal { tenant_id: String, client_hash: [u8;32], upstream_user: String, upstream_password: String }
pub struct RedisIdentityRegistry { users: HashMap<String, Principal> }
impl RedisIdentityRegistry {
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let raw=std::fs::read(path)?;
        let root:serde_json::Value=serde_json::from_slice(&raw).map_err(invalid)?;
        let records=root.get("users").and_then(|v|v.as_array()).ok_or_else(||invalid("users array required"))?;
        if records.is_empty(){return Err(invalid("at least one Redis principal is required"));}
        let mut users=HashMap::new();
        let mut tenant_users=HashMap::new();
        let mut upstream_tenants=HashMap::new();
        for (i,r) in records.iter().enumerate(){
            let field=|k:&str|->io::Result<String>{r.get(k).and_then(|v|v.as_str()).map(str::trim).filter(|v|!v.is_empty()).map(str::to_owned).ok_or_else(||invalid(format!("users[{i}].{k} is required")))};
            let username=field("username")?; let tenant_id=field("tenant_id")?;
            let hash=hex::decode(field("client_password_sha256")?).map_err(invalid)?;
            let client_hash:[u8;32]=hash.try_into().map_err(|_|invalid(format!("users[{i}].client_password_sha256 must be 32 bytes")))?;
            let upstream_user=field("upstream_username")?; let upstream_password=field("upstream_password")?;
            if username.len()>128 || tenant_id.len()>256 || upstream_user.len()>128 || username.bytes().any(|b|!b.is_ascii_graphic()) || upstream_user.bytes().any(|b|!b.is_ascii_graphic()) {return Err(invalid(format!("users[{i}] contains an invalid identifier")));}
            if users.contains_key(&username){return Err(invalid("duplicate Redis gateway username"));}
            if let Some(old)=tenant_users.insert(tenant_id.clone(),upstream_user.clone()){if old!=upstream_user{return Err(invalid("one tenant cannot map to multiple upstream Redis ACL users"));}}
            if let Some(old_tenant)=upstream_tenants.insert(upstream_user.clone(),tenant_id.clone()){if old_tenant!=tenant_id{return Err(invalid("upstream Redis ACL users must be unique per tenant"));}}
            users.insert(username,Principal{tenant_id,client_hash,upstream_user,upstream_password});
        }
        Ok(Self{users})
    }
    fn authenticate(&self,user:&str,password:&[u8])->Option<Principal>{
        let p=self.users.get(user)?;
        let got=Sha256::digest(password);
        let mut diff=0u8; for (a,b) in got.iter().zip(p.client_hash.iter()){diff|=a^b;}
        if diff==0 {Some(p.clone())} else {None}
    }
    pub fn principal_count(&self)->usize{self.users.len()}
}
fn invalid(e:impl std::fmt::Display)->io::Error{io::Error::new(io::ErrorKind::InvalidData,e.to_string())}

struct Config{listen:SocketAddr,upstream:String,upstream_name:String,ca:String,cert:String,key:String,max:usize}
impl Config{
 fn load()->io::Result<Self>{
  let get=|k:&str|std::env::var(k).map_err(|_|io::Error::new(io::ErrorKind::InvalidInput,format!("{k} is required")) );
  let listen=std::env::var("PROXIMA_REDIS_LISTEN_ADDR").unwrap_or_else(|_|"127.0.0.1:6380".into()).parse().map_err(invalid)?;
  let max=std::env::var("PROXIMA_REDIS_MAX_CONNECTIONS").unwrap_or_else(|_|"128".into()).parse::<usize>().map_err(invalid)?;
  if max==0{return Err(invalid("PROXIMA_REDIS_MAX_CONNECTIONS must be positive"));}
  Ok(Self{listen,upstream:get("PROXIMA_REDIS_UPSTREAM_ADDR")?,upstream_name:get("PROXIMA_REDIS_UPSTREAM_TLS_SERVER_NAME")?,ca:get("PROXIMA_REDIS_UPSTREAM_TLS_CA_FILE")?,cert:get("PROXIMA_REDIS_TLS_CERT_FILE")?,key:get("PROXIMA_REDIS_TLS_KEY_FILE")?,max})
 }
}
pub async fn run_redis_gateway()->io::Result<()>{
 let _=rustls::crypto::ring::default_provider().install_default();
 let cfg=Config::load()?;
 let path=std::env::var("PROXIMA_REDIS_IDENTITY_REGISTRY").map_err(invalid)?;
 let registry=Arc::new(RedisIdentityRegistry::load(path)?);
 let acceptor=TlsAcceptor::from(Arc::new(server_tls(&cfg.cert,&cfg.key)?));
 let connector=TlsConnector::from(Arc::new(client_tls(&cfg.ca)?));
 let listener=TcpListener::bind(cfg.listen).await?;
 let permits=Arc::new(Semaphore::new(cfg.max));
 info!(listen=%cfg.listen,upstream=%cfg.upstream,principals=registry.principal_count(),max_connections=cfg.max,"Proxima Redis RESP2 gateway listening");
 loop{
  let (socket,peer)=listener.accept().await?;
  let permit=match permits.clone().try_acquire_owned(){Ok(p)=>p,Err(_)=>{warn!(%peer,"Redis gateway connection limit reached");drop(socket);continue;}};
  let (a,c,r,u,n)=(acceptor.clone(),connector.clone(),registry.clone(),cfg.upstream.clone(),cfg.upstream_name.clone());
  tokio::spawn(async move{let _permit=permit;if let Err(e)=session(socket,a,c,r,&u,&n).await{warn!(%peer,%e,"Redis gateway session closed");}});
 }
}
async fn session(socket:TcpStream,acceptor:TlsAcceptor,connector:TlsConnector,registry:Arc<RedisIdentityRegistry>,upstream_addr:&str,server_name:&str)->io::Result<()>{
 let mut client:Io=Box::new(timeout(Duration::from_secs(10),acceptor.accept(socket)).await.map_err(|_|io::ErrorKind::TimedOut)??);
 let mut input=Vec::new();
 let principal=loop{
  let args=timeout(Duration::from_secs(10),read_command(&mut *client,&mut input)).await.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"Redis authentication timed out"))??;
  let cmd=std::str::from_utf8(args.first().ok_or_else(||invalid("empty command"))?).map_err(invalid)?.to_ascii_uppercase();
  if cmd!="AUTH"{write_error(&mut *client,"authentication required").await?;continue;}
  let (user,password)=match args.as_slice(){[_,p]=>( "default",p.as_slice()),[_,u,p]=>(std::str::from_utf8(u).map_err(invalid)?,p.as_slice()),_=>{write_error(&mut *client,"invalid AUTH arguments").await?;continue;}};
  if let Some(p)=registry.authenticate(user,password){break p;}
  write_error(&mut *client,"invalid credentials").await?;
 };
 let tcp=timeout(Duration::from_secs(10),TcpStream::connect(upstream_addr)).await.map_err(|_|io::ErrorKind::TimedOut)??;
 let name=ServerName::try_from(server_name.to_owned()).map_err(invalid)?;
 let mut upstream:Io=Box::new(timeout(Duration::from_secs(10),connector.connect(name,tcp)).await.map_err(|_|io::ErrorKind::TimedOut)??);
 let auth=vec![b"AUTH".to_vec(),principal.upstream_user.as_bytes().to_vec(),principal.upstream_password.as_bytes().to_vec()];
 upstream.write_all(&encode_command(&auth)).await?; upstream.flush().await?;
 let reply=timeout(Duration::from_secs(30),read_resp_frame(&mut *upstream,0)).await.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"Redis upstream response timed out"))??;
 if !reply.starts_with(b"+OK\r\n"){return Err(io::Error::new(io::ErrorKind::PermissionDenied,"upstream Redis ACL authentication failed"));}
 client.write_all(b"+OK\r\n").await?; client.flush().await?;
 loop{
  let mut args=match timeout(Duration::from_secs(60),read_command(&mut *client,&mut input)).await{Ok(Ok(v))=>v,Ok(Err(e)) if e.kind()==io::ErrorKind::UnexpectedEof=>return Ok(()),Ok(Err(e))=>return Err(e),Err(_)=>return Err(io::Error::new(io::ErrorKind::TimedOut,"Redis client idle timeout"))};
  let cmd=std::str::from_utf8(&args[0]).map_err(invalid)?.to_ascii_uppercase();
  match cmd.as_str(){
   "PING"=>{if args.len()>2{write_error(&mut *client,"wrong number of arguments").await?;}else if args.len()==2{let mut out=b"$".to_vec();out.extend_from_slice(args[1].len().to_string().as_bytes());out.extend_from_slice(b"\r\n");out.extend_from_slice(&args[1]);out.extend_from_slice(b"\r\n");client.write_all(&out).await?;}else{client.write_all(b"+PONG\r\n").await?;}client.flush().await?;continue;},
   "QUIT"=>{client.write_all(b"+OK\r\n").await?;client.flush().await?;return Ok(());},
   "CLIENT" if args.len()==4 && args[1].eq_ignore_ascii_case(b"SETINFO") && (args[2].eq_ignore_ascii_case(b"LIB-NAME") || args[2].eq_ignore_ascii_case(b"LIB-VER"))=>{client.write_all(b"+OK\r\n").await?;client.flush().await?;continue;},
   _=>{}
  }
  if rewrite_keys(&mut args,&principal.tenant_id).is_err(){write_error(&mut *client,"command is not in the tenant-safe allowlist").await?;continue;}
  let frame=encode_command(&args);
  if frame.len()>MAX_FRAME_BYTES{return Err(invalid("rewritten Redis frame exceeds limit"));}
  timeout(Duration::from_secs(10),upstream.write_all(&frame)).await.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"Redis upstream write timed out"))??;upstream.flush().await?;
  let reply=timeout(Duration::from_secs(30),read_resp_frame(&mut *upstream,0)).await.map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"Redis upstream response timed out"))??;
  client.write_all(&reply).await?;client.flush().await?;
 }
}
async fn read_command<R:AsyncRead+Unpin>(r:&mut R,buf:&mut Vec<u8>)->io::Result<Vec<Vec<u8>>>{
 loop{
  match parse_command(buf){Ok(Some((args,n)))=>{buf.drain(..n);return Ok(args)},Ok(None)=>{},Err(e)=>return Err(invalid(format!("invalid RESP command: {e:?}")))}
  if buf.len()>=MAX_FRAME_BYTES{return Err(invalid("RESP request exceeds frame limit"));}
  let mut chunk=[0u8;8192];let n=r.read(&mut chunk).await?;if n==0{return Err(io::ErrorKind::UnexpectedEof.into());}buf.extend_from_slice(&chunk[..n]);
 }
}
async fn line<R:AsyncRead+Unpin>(r:&mut R)->io::Result<Vec<u8>>{let mut v=Vec::new();loop{let b=r.read_u8().await?;v.push(b);if v.len()>128{return Err(invalid("RESP line too long"));}if v.ends_with(b"\r\n"){v.truncate(v.len()-2);return Ok(v);}}}
fn read_resp_frame<'a,R:AsyncRead+Unpin+Send>(r:&'a mut R,depth:usize)->Pin<Box<dyn Future<Output=io::Result<Vec<u8>>>+Send+'a>>{Box::pin(async move {
 if depth>32{return Err(invalid("RESP nesting limit exceeded"));}
 let ty=r.read_u8().await?;let mut out=vec![ty];
 match ty{
  b'+'|b'-'|b':'=>{let l=line(r).await?;out.extend_from_slice(&l);out.extend_from_slice(b"\r\n");},
  b'$'=>{let l=line(r).await?;let n=std::str::from_utf8(&l).map_err(invalid)?.parse::<i64>().map_err(invalid)?;out.extend_from_slice(&l);out.extend_from_slice(b"\r\n");if n>=0{if n as usize>MAX_FRAME_BYTES{return Err(invalid("RESP bulk reply too large"));}let mut b=vec![0;(n as usize)+2];r.read_exact(&mut b).await?;if !b.ends_with(b"\r\n"){return Err(invalid("invalid RESP bulk terminator"));}out.extend_from_slice(&b);}},
  b'*'=>{let l=line(r).await?;let n=std::str::from_utf8(&l).map_err(invalid)?.parse::<i64>().map_err(invalid)?;out.extend_from_slice(&l);out.extend_from_slice(b"\r\n");if n>=0{if n>1024{return Err(invalid("RESP array too large"));}for _ in 0..n{let child=read_resp_frame(r,depth+1).await?;out.extend_from_slice(&child);if out.len()>MAX_FRAME_BYTES{return Err(invalid("RESP reply too large"));}}}},
  _=>return Err(invalid("upstream returned unsupported RESP3 or invalid frame")),
 }
 if out.len()>MAX_FRAME_BYTES{return Err(invalid("RESP reply too large"));}Ok(out)
})}
async fn write_error<W:AsyncWrite+Unpin>(w:&mut W,msg:&str)->io::Result<()>{let safe=msg.replace('\r'," ").replace('\n'," ");w.write_all(format!("-ERR {safe}\r\n").as_bytes()).await?;w.flush().await}
fn server_tls(cert:&str,key:&str)->io::Result<ServerConfig>{
 let certs=rustls_pemfile::certs(&mut BufReader::new(File::open(cert)?)).collect::<Result<Vec<CertificateDer<'static>>,_>>().map_err(invalid)?;
 let key=rustls_pemfile::private_key(&mut BufReader::new(File::open(key)?)).map_err(invalid)?.ok_or_else(||invalid("TLS private key missing"))?;
 ServerConfig::builder().with_no_client_auth().with_single_cert(certs,key).map_err(invalid)
}
fn client_tls(ca:&str)->io::Result<ClientConfig>{
 let mut roots=RootCertStore::empty();let certs=rustls_pemfile::certs(&mut BufReader::new(File::open(ca)?)).collect::<Result<Vec<CertificateDer<'static>>,_>>().map_err(invalid)?;
 for cert in certs{roots.add(cert).map_err(invalid)?;}
 Ok(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
}
