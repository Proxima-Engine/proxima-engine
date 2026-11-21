use mysql_async::{prelude::Queryable, Opts, Pool};

async fn verify_tenant(
    username: &str,
    password: &str,
    own_secret: &str,
    other_database: &str,
    own_prepared_value: &str,
    prepared_id: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let own_database = if username == "client_a" {
        "tenant_a"
    } else {
        "tenant_b"
    };

    let url = format!(
        "mysql://{}:{}@127.0.0.1:3307/{}",
        username, password, own_database
    );

    let pool = Pool::new(Opts::from_url(&url)?);
    let mut conn = pool.get_conn().await?;

    // Own-tenant read.
    let own: Option<String> = conn
        .query_first("SELECT value FROM records WHERE id = 1")
        .await?;

    assert_eq!(own.as_deref(), Some(own_secret));

    // Cross-tenant read must fail.
    let cross_read = conn
        .query_drop(format!("SELECT * FROM {}.records", other_database))
        .await;

    assert!(
        cross_read.is_err(),
        "{username} unexpectedly read another tenant's database"
    );

    // Cross-tenant write must fail.
    let cross_write = conn
        .query_drop(format!(
            "INSERT INTO {}.records (id, value) VALUES (99, 'intrusion')",
            other_database
        ))
        .await;

    assert!(
        cross_write.is_err(),
        "{username} unexpectedly wrote to another tenant's database"
    );

    // Database switching must fail.
    let switch = conn.query_drop(format!("USE {}", other_database)).await;

    assert!(
        switch.is_err(),
        "{username} unexpectedly switched databases"
    );

    // Connection must remain bound to its original tenant.
    let after_denials: Option<String> = conn
        .query_first("SELECT value FROM records WHERE id = 1")
        .await?;

    assert_eq!(after_denials.as_deref(), Some(own_secret));

    // Prepared SELECT.
    let select = conn.prep("SELECT value FROM records WHERE id = ?").await?;

    let prepared_result: Option<String> = conn.exec_first(&select, (1,)).await?;

    assert_eq!(prepared_result.as_deref(), Some(own_secret));

    // Prepared INSERT.
    let insert = conn
        .prep("INSERT INTO records (id, value) VALUES (?, ?)")
        .await?;

    conn.exec_drop(&insert, (prepared_id, own_prepared_value))
        .await?;

    let inserted: Option<String> = conn
        .query_first(format!(
            "SELECT value FROM records WHERE id = {}",
            prepared_id
        ))
        .await?;

    assert_eq!(inserted.as_deref(), Some(own_prepared_value));

    drop(conn);
    pool.disconnect().await?;

    Ok(())
}

async fn verify_caching_sha2_rejects_wrong_password() -> Result<(), Box<dyn std::error::Error>> {
    let pool = Pool::new(Opts::from_url(
        "mysql://client_a:DefinitelyWrongPassword@127.0.0.1:3307/tenant_a",
    )?);
    assert!(
        pool.get_conn().await.is_err(),
        "gateway accepted an invalid caching_sha2_password response"
    );
    pool.disconnect().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable MySQL 8.0 and running Proxima MySQL gateway"]
async fn mysql_gateway_enforces_two_tenant_isolation_and_prepared_statements(
) -> Result<(), Box<dyn std::error::Error>> {
    verify_caching_sha2_rejects_wrong_password().await?;

    verify_tenant(
        "client_a",
        "ClientPassA2026",
        "tenant-a-secret",
        "tenant_b",
        "tenant-a-prepared",
        2,
    )
    .await?;

    verify_tenant(
        "client_b",
        "ClientPassB2026",
        "tenant-b-secret",
        "tenant_a",
        "tenant-b-prepared",
        2,
    )
    .await?;

    Ok(())
}
