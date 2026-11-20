use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::error::Error;
use std::process::{Child, Command};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_postgres::{config::SslMode, Client, NoTls};

type HmacSha256 = Hmac<Sha256>;

const SECRET: &[u8] = b"01234567890123456789012345678901";
fn allocate_proxima_port() -> Result<u16, Box<dyn Error>> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

fn token(tenant_id: &str) -> String {
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3_600;
    let payload = format!("v1.{tenant_id}.{expires_at}");
    let mut mac = HmacSha256::new_from_slice(SECRET).unwrap();
    mac.update(payload.as_bytes());

    let signature = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    format!("{payload}.{signature}")
}

async fn setup_database() -> Result<(), Box<dyn Error>> {
    let (client, connection) = tokio_postgres::Config::new()
        .host("127.0.0.1")
        .port(5432)
        .user("proxima")
        .password("proxima-dev-only")
        .dbname("proxima_dev")
        .connect(NoTls)
        .await?;

    tokio::spawn(async move {
        let _ = connection.await;
    });

    client.batch_execute(
        r#"
        DROP SCHEMA IF EXISTS proxima_e2e CASCADE;
        DO 'BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ''proxima_tenant_tenant_a'') THEN
                CREATE ROLE proxima_tenant_tenant_a LOGIN PASSWORD ''tenant-a-password'' NOSUPERUSER NOBYPASSRLS;
            END IF;
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ''proxima_tenant_tenant_b'') THEN
                CREATE ROLE proxima_tenant_tenant_b LOGIN PASSWORD ''tenant-b-password'' NOSUPERUSER NOBYPASSRLS;
            END IF;
        END';

        ALTER ROLE proxima_tenant_tenant_a LOGIN PASSWORD 'tenant-a-password';
        ALTER ROLE proxima_tenant_tenant_b LOGIN PASSWORD 'tenant-b-password';
        CREATE SCHEMA proxima_e2e;

        CREATE TABLE proxima_e2e.records (
            id serial PRIMARY KEY,
            tenant_id text NOT NULL,
            secret text NOT NULL
        );

        INSERT INTO proxima_e2e.records (tenant_id, secret)
        VALUES ('tenant_a', 'A-secret'), ('tenant_b', 'B-secret');

        ALTER TABLE proxima_e2e.records ENABLE ROW LEVEL SECURITY;
        ALTER TABLE proxima_e2e.records FORCE ROW LEVEL SECURITY;

        CREATE POLICY tenant_a_policy ON proxima_e2e.records
            FOR ALL TO proxima_tenant_tenant_a
            USING (tenant_id = 'tenant_a')
            WITH CHECK (tenant_id = 'tenant_a');

        CREATE POLICY tenant_b_policy ON proxima_e2e.records
            FOR ALL TO proxima_tenant_tenant_b
            USING (tenant_id = 'tenant_b')
            WITH CHECK (tenant_id = 'tenant_b');

        GRANT USAGE ON SCHEMA proxima_e2e TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
        GRANT SELECT, INSERT, UPDATE, DELETE ON proxima_e2e.records TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
        GRANT USAGE, SELECT ON SEQUENCE proxima_e2e.records_id_seq TO proxima_tenant_tenant_a, proxima_tenant_tenant_b;
        "#,
    )
    .await?;

    let role_count: i64 = client
        .query_one(
            "SELECT count(*) FROM pg_roles WHERE rolname IN ('proxima_tenant_tenant_a', 'proxima_tenant_tenant_b')",
            &[],
        )
        .await?
        .get(0);
    assert_eq!(role_count, 2, "tenant roles were not created");

    Ok(())
}

async fn connect_tenant(
    tenant_id: &str,
    password: &str,
    port: u16,
) -> Result<Client, Box<dyn Error>> {
    let mut config = tokio_postgres::Config::new();
    config
        .host("127.0.0.1")
        .port(port)
        .user("proxima")
        .password(password)
        .dbname("proxima_dev")
        .ssl_mode(SslMode::Disable)
        .options(format!("-c proxima_tenant_token={}", token(tenant_id)));

    let (client, connection) = config.connect(NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    Ok(client)
}

fn start_proxima(port: u16) -> Result<Child, Box<dyn Error>> {
    let binary = env!("CARGO_BIN_EXE_proxima-engine");
    let child = Command::new(binary)
        .env("PROXIMA_LISTEN_ADDR", format!("127.0.0.1:{port}"))
        .env("PROXIMA_UPSTREAM_ADDR", "127.0.0.1:5432")
        .env("PROXIMA_TENANT_SIGNING_KEY", std::str::from_utf8(SECRET)?)
        .env("RUST_LOG", "proxima_engine=warn")
        .spawn()?;
    Ok(child)
}

async fn wait_for_port(port: u16) -> Result<(), Box<dyn Error>> {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    Err("Proxima did not start listening".into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_session_enforces_tenant_isolation() -> Result<(), Box<dyn Error>> {
    setup_database().await?;

    let proxima_port = allocate_proxima_port()?;
    let mut proxima = start_proxima(proxima_port)?;

    let result = async {
        wait_for_port(proxima_port).await?;

        let tenant_a = connect_tenant("tenant_a", "tenant-a-password", proxima_port).await?;
        let tenant_b = connect_tenant("tenant_b", "tenant-b-password", proxima_port).await?;

        let a_visible = tenant_a
            .query_one(
                "SELECT string_agg(secret, ',' ORDER BY secret) FROM proxima_e2e.records",
                &[],
            )
            .await?;
        assert_eq!(
            a_visible.get::<_, Option<String>>(0).as_deref(),
            Some("A-secret")
        );

        let a_cross = tenant_a
            .query_one(
                "SELECT count(*) FROM proxima_e2e.records WHERE tenant_id = 'tenant_b'",
                &[],
            )
            .await?;
        assert_eq!(a_cross.get::<_, i64>(0), 0);

        let b_visible = tenant_b
            .query_one(
                "SELECT string_agg(secret, ',' ORDER BY secret) FROM proxima_e2e.records",
                &[],
            )
            .await?;
        assert_eq!(
            b_visible.get::<_, Option<String>>(0).as_deref(),
            Some("B-secret")
        );

        let b_cross = tenant_b
            .query_one(
                "SELECT count(*) FROM proxima_e2e.records WHERE tenant_id = 'tenant_a'",
                &[],
            )
            .await?;
        assert_eq!(b_cross.get::<_, i64>(0), 0);

        let a_prepared = tenant_a
            .query_one(
                "SELECT count(*) FROM proxima_e2e.records WHERE tenant_id = $1",
                &[&"tenant_b"],
            )
            .await?;
        assert_eq!(a_prepared.get::<_, i64>(0), 0);

        let insert = tenant_a
            .execute(
                "INSERT INTO proxima_e2e.records (tenant_id, secret) VALUES ($1, $2)",
                &[&"tenant_b", &"forbidden"],
            )
            .await;
        assert!(
            insert.is_err(),
            "cross-tenant insert unexpectedly succeeded"
        );

        Ok::<(), Box<dyn Error>>(())
    }
    .await;

    let _ = proxima.kill();
    let _ = proxima.wait();

    result
}
