use proxima_mysql_gateway::{
    auth::generate_gateway_credential,
    isolation::{build_provisioning_plan, generate_mysql_password, MySqlTenantIdentity},
    provisioning::{
        execute_provisioning_with_finalize, FileProvisioningJournal, MySqlAdminExecutor,
    },
    store::EncryptedTenantStore,
    tenant::TenantAssertion,
    upstream::UpstreamTlsConfig,
};
use std::{
    env,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::runtime::Runtime;
use zeroize::Zeroize;

fn required(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("required environment variable {name} is missing"))?;
    let value = value.trim().to_owned();
    if value.is_empty() { return Err(format!("required environment variable {name} is empty")); }
    Ok(value)
}

fn number(name: &str, default: u64) -> Result<u64, String> {
    env::var(name)
        .map(|value| value.parse::<u64>().map_err(|_| format!("{name} must be an unsigned integer")))
        .unwrap_or(Ok(default))
}

fn upstream_config() -> Result<UpstreamTlsConfig, String> {
    let host = required("PROXIMA_MYSQL_UPSTREAM_HOST")?;
    let port = env::var("PROXIMA_MYSQL_UPSTREAM_PORT")
        .unwrap_or_else(|_| "3306".into())
        .parse::<u16>()
        .map_err(|_| "PROXIMA_MYSQL_UPSTREAM_PORT must be a valid TCP port".to_owned())?;
    let server_name = required("PROXIMA_MYSQL_UPSTREAM_SERVER_NAME")?;
    let ca_file = required("PROXIMA_MYSQL_UPSTREAM_CA_FILE")?;
    let max_packet_size = env::var("PROXIMA_MYSQL_MAX_PACKET_SIZE")
        .unwrap_or_else(|_| "16777214".into())
        .parse::<usize>()
        .map_err(|_| "PROXIMA_MYSQL_MAX_PACKET_SIZE must be an unsigned integer".to_owned())?;
    UpstreamTlsConfig::from_ca_file(
        host, port, server_name, &ca_file,
        Duration::from_millis(number("PROXIMA_MYSQL_CONNECT_TIMEOUT_MS", 10_000)?),
        Duration::from_millis(number("PROXIMA_MYSQL_HANDSHAKE_TIMEOUT_MS", 10_000)?),
        max_packet_size,
    ).map_err(|_| "invalid MySQL upstream TLS configuration".to_owned())
}

fn open_store() -> Result<Arc<EncryptedTenantStore>, String> {
    let store_path = PathBuf::from(required("PROXIMA_MYSQL_SECRET_STORE_FILE")?);
    let key_path = PathBuf::from(required("PROXIMA_MYSQL_SECRET_STORE_KEY_FILE")?);
    EncryptedTenantStore::open(store_path, key_path)
        .map(Arc::new)
        .map_err(|error| format!("cannot open encrypted MySQL tenant store: {error}"))
}

fn main() {
    let mut args = env::args().skip(1);
    let command = args.next();
    let result = match command.as_deref() {
        Some("provision") => {
            let tenant = args.next();
            let gateway_username = args.next();
            match (tenant, gateway_username, args.next()) {
                (Some(tenant), Some(username), None) => {
                    let runtime = Runtime::new().map_err(|error| error.to_string());
                    match runtime {
                        Ok(runtime) => runtime.block_on(provision(tenant, username)),
                        Err(error) => Err(error),
                    }
                }
                _ => Err("usage: proxima-mysql-admin provision <tenant-uuid> <gateway-username>".into()),
            }
        }
        _ => Err("usage: proxima-mysql-admin provision <tenant-uuid> <gateway-username>".into()),
    };
    if let Err(error) = result {
        eprintln!("MySQL provisioning failed: {error}");
        std::process::exit(1);
    }
}

async fn provision(tenant_value: String, gateway_username: String) -> Result<(), String> {
    let tenant_id = uuid::Uuid::parse_str(&tenant_value)
        .map_err(|_| "tenant ID must be a UUID".to_owned())?;
    if gateway_username.is_empty()
        || gateway_username.len() > 32
        || !gateway_username.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("gateway username must contain 1-32 ASCII letters, digits or underscores".into());
    }

    let account_host = required("PROXIMA_MYSQL_ACCOUNT_HOST")?;
    let admin_username = required("PROXIMA_MYSQL_PROVISIONING_USER")?;
    let mut admin_password = required("PROXIMA_MYSQL_PROVISIONING_PASSWORD")?;
    let mut runtime_password = generate_mysql_password()
        .map_err(|_| "operating-system random source unavailable".to_owned())?;
    let mut migration_password = generate_mysql_password()
        .map_err(|_| "operating-system random source unavailable".to_owned())?;
    let gateway_credential = generate_gateway_credential()
        .map_err(|_| "operating-system random source unavailable".to_owned())?;

    let identity = MySqlTenantIdentity::for_tenant(tenant_id);
    let plan = build_provisioning_plan(
        tenant_id,
        &account_host,
        &runtime_password,
        &migration_password,
    ).map_err(|error| error.to_string())?;

    let upstream = upstream_config()?;
    let mut executor = MySqlAdminExecutor::connect(
        &upstream,
        &admin_username,
        &admin_password,
        Duration::from_millis(number("PROXIMA_MYSQL_STATEMENT_TIMEOUT_MS", 30_000)?),
    ).await.map_err(|_| "could not authenticate to MySQL with the provisioning account over verified TLS".to_owned())?;
    admin_password.zeroize();

    let store = open_store()?;
    let journal_path = PathBuf::from(required("PROXIMA_MYSQL_PROVISIONING_JOURNAL_FILE")?);
    let mut journal = FileProvisioningJournal::open(journal_path)
        .map_err(|_| "cannot open secure MySQL provisioning journal".to_owned())?;

    let finalize_store = Arc::clone(&store);
    let rollback_store = Arc::clone(&store);
    let username_for_store = gateway_username.clone();
    let runtime_username = identity.runtime_username.clone();
    let migration_username = identity.migration_username.clone();
    let runtime_password_for_store = runtime_password.clone();
    let migration_password_for_store = migration_password.clone();

    let (created, gateway_password) = execute_provisioning_with_finalize(
        &plan,
        &mut executor,
        &mut journal,
        move |identity| {
            finalize_store.register_tenant(
                identity.tenant_id,
                &username_for_store,
                gateway_credential,
                &runtime_username,
                &runtime_password_for_store,
                &migration_username,
                &migration_password_for_store,
            ).map_err(|_| ())
        },
        move |identity, _gateway_password| {
            rollback_store.revoke_tenant(identity.tenant_id).map_err(|_| ())
        },
    ).await.map_err(|error| error.to_string())?;

    runtime_password.zeroize();
    migration_password.zeroize();

    println!("MySQL tenant provisioning completed.");
    println!("Tenant ID: {}", created.tenant_id);
    println!("Database: {}", created.database_name);
    println!("Gateway username: {gateway_username}");
    println!("Gateway password (shown once): {gateway_password}");
    println!("Gateway endpoint: {}", env::var("PROXIMA_MYSQL_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:13306".into()));
    println!("The upstream runtime and migration passwords are encrypted in the local secret store and were not printed.");

    if env::var("PROXIMA_MYSQL_ISSUE_LOCAL_ASSERTION").ok().as_deref() == Some("true") {
        let encoded = required("PROXIMA_MYSQL_TENANT_ASSERTION_KEY")?;
        if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("PROXIMA_MYSQL_TENANT_ASSERTION_KEY must be exactly 64 hexadecimal characters".into());
        }
        let key = hex::decode(encoded).map_err(|_| "invalid tenant assertion key".to_owned())?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch".to_owned())?.as_secs();
        let assertion = TenantAssertion::issue(created.tenant_id, now + 900, &key)
            .map_err(|_| "could not issue local tenant assertion".to_owned())?;
        println!("LOCAL DEVELOPMENT ASSERTION (15 minutes): {assertion}");
        println!("Do not enable local assertion issuance in production; production assertions must come from the authenticated Control Plane.");
    } else {
        println!("Tenant assertion: obtain it from the authenticated Agata Control Plane. Local assertion issuance is disabled.");
    }

    Ok(())
}
