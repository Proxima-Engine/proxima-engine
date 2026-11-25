use proxima_engine::sqlserver_tenant::{
    SqlServerExecutor, SqlServerTenant, TiberiusSqlServerExecutor,
};
use uuid::Uuid;

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is required for SQL Server acceptance"))
}

#[tokio::test]
#[ignore = "requires disposable SQL Server 2022/2019 with TLS and a provisioning administrator"]
async fn sqlserver_native_lifecycle_is_tenant_scoped_and_revocable() {
    let host = required("PROXIMA_SQLSERVER_HOST");
    let port = std::env::var("PROXIMA_SQLSERVER_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1433);
    let admin_user = required("PROXIMA_SQLSERVER_ADMIN_USER");
    let admin_password = required("PROXIMA_SQLSERVER_ADMIN_PASSWORD");
    let mut executor =
        TiberiusSqlServerExecutor::new(&host, port, &admin_user, &admin_password).unwrap();
    if let Ok(path) = std::env::var("PROXIMA_SQLSERVER_CA_FILE") {
        let bytes = std::fs::read(path).expect("read SQL Server CA file");
        executor = executor.with_ca_bundle(bytes).unwrap();
    }

    let suffix = &Uuid::new_v4().simple().to_string()[..12];
    let tenant_a_id = format!("ci_a_{suffix}");
    let tenant_b_id = format!("ci_b_{suffix}");
    let password_a = format!("Agata-A-{}-!x9", Uuid::new_v4().simple());
    let password_b = format!("Agata-B-{}-!x9", Uuid::new_v4().simple());
    let mut tenant_a = SqlServerTenant::new(&tenant_a_id, &password_a).unwrap();
    let tenant_b = SqlServerTenant::new(&tenant_b_id, &password_b).unwrap();

    let result = async {
        tenant_a.provision(&executor).await.unwrap();
        tenant_b.provision(&executor).await.unwrap();
        tenant_a.verify(&executor).await.unwrap();
        tenant_b.verify(&executor).await.unwrap();

        assert!(executor
            .user_mapped(tenant_a.database(), tenant_a.login())
            .await
            .unwrap());
        assert!(!executor
            .user_mapped(tenant_a.database(), tenant_b.login())
            .await
            .unwrap());
        assert!(!executor
            .user_mapped(tenant_b.database(), tenant_a.login())
            .await
            .unwrap());
        assert!(!executor
            .has_elevated_role(tenant_a.database(), tenant_a.login(), "db_owner")
            .await
            .unwrap());
        assert!(!executor
            .has_elevated_role(tenant_a.database(), tenant_a.login(), "sysadmin")
            .await
            .unwrap());

        let rotated = format!("Agata-R-{}-!x9", Uuid::new_v4().simple());
        tenant_a.rotate(&executor, &rotated).await.unwrap();
        tenant_a.revoke(&executor).await.unwrap();
        assert!(!executor.login_enabled(tenant_a.login()).await.unwrap());
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    // Always remove disposable test resources, even if an assertion or lifecycle
    // operation fails. The tenant data in this test is disposable by definition.
    let cleanup_a = tenant_a.destroy(&executor).await;
    let cleanup_b = tenant_b.destroy(&executor).await;
    if let Err(error) = result {
        panic!("SQL Server acceptance failed: {error}");
    }
    cleanup_a.unwrap();
    cleanup_b.unwrap();
}
