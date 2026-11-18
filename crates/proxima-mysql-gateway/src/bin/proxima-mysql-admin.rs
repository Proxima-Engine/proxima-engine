use proxima_mysql_gateway::{
    auth::{
        generate_gateway_credential, TenantMigrationCredentialStore,
        TenantUpstreamCredentialStore,
    },
    isolation::{
        build_password_rotation, build_provisioning_plan, build_revocation,
        generate_mysql_password, MySqlTenantIdentity,
    },
    provisioning::{
        execute_provisioning_with_finalize, FileProvisioningJournal,
        MySqlAdminExecutor, MySqlDdlExecutor,
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
use zeroize::{Zeroize, Zeroizing};

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
        Some("revoke") => {
            let tenant = args.next();
            match (tenant, args.next()) {
                (Some(tenant), None) => match Runtime::new() {
                    Ok(runtime) => runtime.block_on(revoke(tenant)),
                    Err(error) => Err(error.to_string()),
                },
                _ => Err("usage: proxima-mysql-admin revoke <tenant-uuid>".into()),
            }
        }
        Some("rotate") => {
            let tenant = args.next();
            let gateway_username = args.next();
            match (tenant, gateway_username, args.next()) {
                (Some(tenant), Some(username), None) => match Runtime::new() {
                    Ok(runtime) => runtime.block_on(rotate(tenant, username)),
                    Err(error) => Err(error.to_string()),
                },
                _ => Err("usage: proxima-mysql-admin rotate <tenant-uuid> <gateway-username>".into()),
            }
        }
        Some("reconcile") => {
            let tenant = args.next();
            let note = args.collect::<Vec<_>>().join(" ");
            match tenant {
                Some(tenant) if !note.trim().is_empty() => reconcile(tenant, note),
                _ => Err("usage: proxima-mysql-admin reconcile <tenant-uuid> <operator-note>".into()),
            }
        }
        Some("rotate-assertion-key") => {
            let tenant = args.next();
            match (tenant, args.next()) {
                (Some(tenant), None) => rotate_assertion_key(tenant),
                _ => Err("usage: proxima-mysql-admin rotate-assertion-key <tenant-uuid>".into()),
            }
        }
        _ => Err("usage: proxima-mysql-admin <provision|rotate|revoke|rotate-assertion-key|reconcile> ...".into()),
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
    let admin_password = Zeroizing::new(required("PROXIMA_MYSQL_PROVISIONING_PASSWORD")?);
    let runtime_password = Zeroizing::new(generate_mysql_password()
        .map_err(|_| "operating-system random source unavailable".to_owned())?);
    let migration_password = Zeroizing::new(generate_mysql_password()
        .map_err(|_| "operating-system random source unavailable".to_owned())?);
    let gateway_credential = generate_gateway_credential()
        .map_err(|_| "operating-system random source unavailable".to_owned())?;
    let mut assertion_key_hex = required("PROXIMA_MYSQL_TENANT_ASSERTION_KEY")?;
    if assertion_key_hex.len() != 64
        || !assertion_key_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        assertion_key_hex.zeroize();
        return Err("PROXIMA_MYSQL_TENANT_ASSERTION_KEY must be a tenant-scoped 32-byte key encoded as 64 hexadecimal characters".into());
    }
    // The existing Control Plane signs with the 64 ASCII hexadecimal
    // characters returned by organization_tenant_signing_key. Preserve those
    // exact bytes; decoding them would produce a different HMAC key.
    let assertion_key = Zeroizing::new(assertion_key_hex.as_bytes().to_vec());
    assertion_key_hex.zeroize();

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

    let store = open_store()?;
    let journal_path = PathBuf::from(required("PROXIMA_MYSQL_PROVISIONING_JOURNAL_FILE")?);
    let mut journal = FileProvisioningJournal::open(journal_path)
        .map_err(|_| "cannot open secure MySQL provisioning journal".to_owned())?;

    let finalize_store = Arc::clone(&store);
    let rollback_store = Arc::clone(&store);
    let username_for_store = gateway_username.clone();
    let runtime_username = identity.runtime_username.clone();
    let migration_username = identity.migration_username.clone();
    let runtime_password_for_store = Zeroizing::new(runtime_password.to_string());
    let migration_password_for_store = Zeroizing::new(migration_password.to_string());
    let assertion_key_for_store = assertion_key.clone();

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
                &assertion_key_for_store,
            ).map(Zeroizing::new).map_err(|_| ())
        },
        move |identity, _gateway_password| {
            rollback_store.revoke_tenant(identity.tenant_id).map_err(|_| ())
        },
    ).await.map_err(|error| error.to_string())?;


    println!("MySQL tenant provisioning completed.");
    println!("Tenant ID: {}", created.tenant_id);
    println!("Database: {}", created.database_name);
    println!("Gateway username: {gateway_username}");
    println!("Gateway password (shown once): {gateway_password}");
    println!("Gateway endpoint: {}", env::var("PROXIMA_MYSQL_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:13306".into()));
    println!("The upstream runtime and migration passwords are encrypted in the local secret store and were not printed.");

    if env::var("PROXIMA_MYSQL_ISSUE_LOCAL_ASSERTION").ok().as_deref() == Some("true") {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch".to_owned())?.as_secs();
        let mut assertion = TenantAssertion::issue(created.tenant_id, now + 3600, &assertion_key)
            .map_err(|_| "could not issue local tenant assertion".to_owned())?;
        println!("LOCAL DEVELOPMENT ASSERTION (60 minutes): {assertion}");
        assertion.zeroize();
        println!("Do not enable local assertion issuance in production; production assertions must come from the authenticated Control Plane.");
    } else {
        println!("Tenant assertion: obtain it from the authenticated Agata Control Plane. Local assertion issuance is disabled.");
    }

    Ok(())
}

async fn revoke(tenant_value: String) -> Result<(), String> {
    let tenant_id = uuid::Uuid::parse_str(&tenant_value)
        .map_err(|_| "tenant ID must be a UUID".to_owned())?;
    let store = open_store()?;

    // Remove the tenant's gateway and upstream secrets first. The running
    // gateway reloads this file at each command boundary and denies new work.
    store.revoke_tenant(tenant_id)
        .map_err(|_| "could not revoke the tenant in the encrypted gateway registry".to_owned())?;

    let account_host = required("PROXIMA_MYSQL_ACCOUNT_HOST")?;
    let admin_password = Zeroizing::new(required("PROXIMA_MYSQL_PROVISIONING_PASSWORD")?);
    let upstream = upstream_config()?;
    let mut executor = MySqlAdminExecutor::connect(
        &upstream,
        &required("PROXIMA_MYSQL_PROVISIONING_USER")?,
        &admin_password,
        Duration::from_millis(number("PROXIMA_MYSQL_STATEMENT_TIMEOUT_MS", 30_000)?),
    ).await.map_err(|_| "tenant secrets are revoked locally, but MySQL administrator connection failed; upstream account cleanup needs reconciliation".to_owned())?;

    let identity = MySqlTenantIdentity::for_tenant(tenant_id);
    let statements = build_revocation(&identity, &account_host)
        .map_err(|_| "invalid MySQL tenant account host".to_owned())?;
    for statement in statements {
        executor.execute(&statement).await
            .map_err(|_| "tenant secrets are revoked locally, but MySQL account locking/grant revocation failed; inspect the upstream accounts".to_owned())?;
    }
    println!("Tenant revoked. New gateway commands are denied; existing in-flight queries may finish.");
    Ok(())
}

async fn rotate(tenant_value: String, gateway_username: String) -> Result<(), String> {
    let tenant_id = uuid::Uuid::parse_str(&tenant_value)
        .map_err(|_| "tenant ID must be a UUID".to_owned())?;
    let store = open_store()?;
    let old_runtime = store.load_runtime_credentials(tenant_id)
        .map_err(|_| "could not read tenant runtime credentials".to_owned())?
        .ok_or_else(|| "tenant runtime credentials are not registered".to_owned())?;
    let old_migration = store.load_migration_credentials(tenant_id)
        .map_err(|_| "could not read tenant migration credentials".to_owned())?
        .ok_or_else(|| "tenant migration credentials are not registered".to_owned())?;

    let identity = MySqlTenantIdentity::for_tenant(tenant_id);
    let new_runtime_password = Zeroizing::new(generate_mysql_password()
        .map_err(|_| "operating-system random source unavailable".to_owned())?);
    let new_migration_password = Zeroizing::new(generate_mysql_password()
        .map_err(|_| "operating-system random source unavailable".to_owned())?);
    let new_gateway_credential = generate_gateway_credential()
        .map_err(|_| "operating-system random source unavailable".to_owned())?;

    let statements = build_password_rotation(
        &identity,
        &required("PROXIMA_MYSQL_ACCOUNT_HOST")?,
        &new_runtime_password,
        &new_migration_password,
    ).map_err(|_| "invalid MySQL tenant credential rotation plan".to_owned())?;

    let admin_password = Zeroizing::new(required("PROXIMA_MYSQL_PROVISIONING_PASSWORD")?);
    let upstream = upstream_config()?;
    let mut executor = MySqlAdminExecutor::connect(
        &upstream,
        &required("PROXIMA_MYSQL_PROVISIONING_USER")?,
        &admin_password,
        Duration::from_millis(number("PROXIMA_MYSQL_STATEMENT_TIMEOUT_MS", 30_000)?),
    ).await.map_err(|_| "could not authenticate to MySQL with the provisioning account over verified TLS".to_owned())?;

    for statement in &statements {
        if executor.execute(statement).await.is_err() {
            // A lost response is ambiguous: MySQL may have applied the ALTER
            // USER before the connection failed. Restore both old passwords,
            // even when the first command appears to have failed.
            let rollback = build_password_rotation(
                &identity,
                &required("PROXIMA_MYSQL_ACCOUNT_HOST")?,
                &old_runtime.password,
                &old_migration.password,
            ).map_err(|_| "credential rotation failed and rollback plan could not be built".to_owned())?;
            let mut rollback_failed = false;
            for rollback_statement in rollback {
                if executor.execute(&rollback_statement).await.is_err() {
                    rollback_failed = true;
                }
            }
            if rollback_failed {
                return Err("credential rotation outcome is ambiguous and MySQL rollback was unsuccessful; manual reconciliation is required".into());
            }
            return Err("MySQL credential rotation failed; previous database credentials were restored".into());
        }
    }

    let gateway_password = Zeroizing::new(match store.rotate_tenant_credentials(
        tenant_id,
        &gateway_username,
        new_gateway_credential,
        &identity.runtime_username,
        &new_runtime_password,
        &identity.migration_username,
        &new_migration_password,
    ) {
        Ok(password) => password,
        Err(_) => {
            let rollback = build_password_rotation(
                &identity,
                &required("PROXIMA_MYSQL_ACCOUNT_HOST")?,
                &old_runtime.password,
                &old_migration.password,
            ).map_err(|_| "credential store update failed and rollback plan could not be built".to_owned())?;
            let mut rollback_failed = false;
            for statement in rollback {
                if executor.execute(&statement).await.is_err() {
                    rollback_failed = true;
                }
            }
            if rollback_failed {
                return Err("credential store update failed and MySQL rollback was unsuccessful; manual reconciliation is required".into());
            }
            return Err("credential store update failed; previous MySQL credentials were restored".into());
        }
    });

    println!("Tenant credentials rotated.");
    println!("Gateway username: {gateway_username}");
    println!("Gateway password (shown once): {gateway_password}");
    println!("Runtime and migration credentials were rotated and stored encrypted; their values were not printed.");
    Ok(())
}

fn rotate_assertion_key(tenant_value: String) -> Result<(), String> {
    let tenant_id = uuid::Uuid::parse_str(&tenant_value)
        .map_err(|_| "tenant ID must be a UUID".to_owned())?;
    let mut encoded = required("PROXIMA_MYSQL_TENANT_ASSERTION_KEY")?;
    if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        encoded.zeroize();
        return Err("PROXIMA_MYSQL_TENANT_ASSERTION_KEY must be 64 ASCII hexadecimal characters".into());
    }
    let key = Zeroizing::new(encoded.as_bytes().to_vec());
    encoded.zeroize();
    let store = open_store()?;
    store.rotate_assertion_key(tenant_id, &key)
        .map_err(|_| "could not rotate the tenant assertion key in the encrypted registry".to_owned())?;
    println!("Tenant assertion verification key updated for {tenant_id}.");
    println!("Coordinate this change with the Control Plane signer before issuing new tenant assertions.");
    Ok(())
}

fn reconcile(tenant_value: String, note: String) -> Result<(), String> {
    let tenant_id = uuid::Uuid::parse_str(&tenant_value)
        .map_err(|_| "tenant ID must be a UUID".to_owned())?;
    let journal_path = PathBuf::from(required("PROXIMA_MYSQL_PROVISIONING_JOURNAL_FILE")?);
    let mut journal = FileProvisioningJournal::open(journal_path)
        .map_err(|_| "cannot open MySQL provisioning journal".to_owned())?;
    journal.acknowledge_reconciliation(&tenant_id.to_string(), &note)
        .map_err(|_| "tenant is not blocked for reconciliation, or the operator note is invalid".to_owned())?;
    println!("Provisioning journal reconciliation acknowledged for tenant {tenant_id}.");
    println!("This command does not modify MySQL databases or accounts. The operator must inspect and reconcile the upstream state before acknowledging.");
    Ok(())
}

