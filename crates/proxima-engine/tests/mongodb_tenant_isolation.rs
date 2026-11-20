use mongodb::bson::{doc, Document};
use mongodb::Client;
use std::error::Error;

const TENANT_A_PASSWORD: &str = "TenantAUpstream2026";
const TENANT_B_PASSWORD: &str = "TenantBUpstream2026";

fn tenant_uri(username: &str, password: &str, database: &str) -> String {
    format!("mongodb://{username}:{password}@127.0.0.1:27017/{database}?authSource=admin&directConnection=true")
}

#[tokio::test]
#[ignore = "requires disposable MongoDB 8 service with root authentication"]
async fn mongo_database_credentials_prevent_cross_tenant_reads_and_writes() -> Result<(), Box<dyn Error>> {
    let root_uri = std::env::var("PROXIMA_MONGODB_TEST_URI")?;
    let root = Client::with_uri_str(&root_uri).await?;
    let admin = root.database("admin");

    // Make the test repeatable if a runner reuses its MongoDB service volume.
    let _ = admin.run_command(doc! { "dropUser": "tenant_a_gateway" }).await;
    let _ = admin.run_command(doc! { "dropUser": "tenant_b_gateway" }).await;
    root.database("tenant_a_db").drop().await?;
    root.database("tenant_b_db").drop().await?;

    root.database("tenant_a_db")
        .collection::<Document>("records")
        .insert_one(doc! { "secret": "tenant-a-only" })
        .await?;
    root.database("tenant_b_db")
        .collection::<Document>("records")
        .insert_one(doc! { "secret": "tenant-b-only" })
        .await?;

    admin.run_command(doc! {
        "createUser": "tenant_a_gateway",
        "pwd": TENANT_A_PASSWORD,
        "roles": [{ "role": "readWrite", "db": "tenant_a_db" }]
    }).await?;
    admin.run_command(doc! {
        "createUser": "tenant_b_gateway",
        "pwd": TENANT_B_PASSWORD,
        "roles": [{ "role": "readWrite", "db": "tenant_b_db" }]
    }).await?;

    let tenant_a = Client::with_uri_str(&tenant_uri("tenant_a_gateway", TENANT_A_PASSWORD, "tenant_a_db")).await?;
    let tenant_b = Client::with_uri_str(&tenant_uri("tenant_b_gateway", TENANT_B_PASSWORD, "tenant_b_db")).await?;

    let a_record = tenant_a.database("tenant_a_db")
        .collection::<Document>("records")
        .find_one(doc! {}).await?
        .ok_or("tenant A record missing")?;
    assert_eq!(a_record.get_str("secret")?, "tenant-a-only");

    let b_record = tenant_b.database("tenant_b_db")
        .collection::<Document>("records")
        .find_one(doc! {}).await?
        .ok_or("tenant B record missing")?;
    assert_eq!(b_record.get_str("secret")?, "tenant-b-only");

    let cross_tenant_read = tenant_a.database("tenant_b_db")
        .run_command(doc! { "find": "records", "filter": {} }).await;
    assert!(cross_tenant_read.is_err(), "tenant A read from tenant B database unexpectedly succeeded");

    let cross_tenant_write = tenant_a.database("tenant_b_db")
        .run_command(doc! {
            "insert": "records",
            "documents": [{ "secret": "cross-tenant-write" }]
        }).await;
    assert!(cross_tenant_write.is_err(), "tenant A write into tenant B database unexpectedly succeeded");

    let enumerate_databases = tenant_a.database("admin")
        .run_command(doc! { "listDatabases": 1 }).await;
    assert!(enumerate_databases.is_err(), "tenant A unexpectedly enumerated server databases");

    // Cleanup with the administrative identity; no tenant identity has elevated privileges.
    let _ = admin.run_command(doc! { "dropUser": "tenant_a_gateway" }).await;
    let _ = admin.run_command(doc! { "dropUser": "tenant_b_gateway" }).await;
    root.database("tenant_a_db").drop().await?;
    root.database("tenant_b_db").drop().await?;
    Ok(())
}
