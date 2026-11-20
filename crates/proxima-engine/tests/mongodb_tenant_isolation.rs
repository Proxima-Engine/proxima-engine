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

    // MongoDB's authenticated listDatabases behavior is intentionally
    // filtered when authorizedDatabases is omitted/true. A tenant with
    // database-scoped roles may receive a successful response containing
    // only databases it is authorized to see; requiring the whole command
    // to fail is incorrect and caused the previous CI assertion to fail.
    let enumerate_authorized = tenant_a.database("admin")
        .run_command(doc! { "listDatabases": 1, "authorizedDatabases": true }).await?;
    let visible_databases = enumerate_authorized
        .get_array("databases")?
        .iter()
        .filter_map(|entry| entry.as_document()?.get_str("name").ok())
        .collect::<Vec<_>>();
    assert!(
        visible_databases.iter().any(|name| *name == "tenant_a_db"),
        "tenant A should see its own authorized database"
    );
    assert!(
        !visible_databases.iter().any(|name| *name == "tenant_b_db"),
        "tenant A was shown tenant B's database"
    );

    // Explicitly disabling authorization filtering must remain forbidden.
    let enumerate_all = tenant_a.database("admin")
        .run_command(doc! { "listDatabases": 1, "authorizedDatabases": false }).await;
    assert!(
        enumerate_all.is_err(),
        "tenant A unexpectedly enumerated unauthorized server databases"
    );

    // Exercise the Proxima wire gateway with real MongoDB driver traffic.
    // The gateway terminates client TLS, binds SCRAM usernames to immutable
    // tenant identities, and forwards authenticated commands over a dedicated
    // upstream connection using the same tenant-scoped MongoDB credentials.
    let gateway_addr = std::env::var("PROXIMA_MONGODB_GATEWAY_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:27018".to_owned());
    let gateway_uri = |username: &str, password: &str, database: &str| {
        format!(
            "mongodb://{username}:{password}@{gateway_addr}/{database}?authSource=admin&tls=true&tlsAllowInvalidCertificates=true&directConnection=true"
        )
    };
    let gateway_a = Client::with_uri_str(&gateway_uri("tenant_a_gateway", TENANT_A_PASSWORD, "tenant_a_db")).await?;
    let gateway_b = Client::with_uri_str(&gateway_uri("tenant_b_gateway", TENANT_B_PASSWORD, "tenant_b_db")).await?;

    let gateway_a_record = gateway_a.database("tenant_a_db")
        .collection::<Document>("records")
        .find_one(doc! {}).await?
        .ok_or("gateway tenant A record missing")?;
    assert_eq!(gateway_a_record.get_str("secret")?, "tenant-a-only");

    let gateway_b_record = gateway_b.database("tenant_b_db")
        .collection::<Document>("records")
        .find_one(doc! {}).await?
        .ok_or("gateway tenant B record missing")?;
    assert_eq!(gateway_b_record.get_str("secret")?, "tenant-b-only");

    let gateway_cross_database_read = gateway_a.database("tenant_b_db")
        .run_command(doc! { "find": "records", "filter": {} }).await;
    assert!(gateway_cross_database_read.is_err(), "gateway tenant A reached tenant B database");

    let gateway_cross_database_lookup = gateway_a.database("tenant_a_db")
        .run_command(doc! {
            "aggregate": "records",
            "pipeline": [{
                "$lookup": {
                    "from": { "db": "tenant_b_db", "coll": "records" },
                    "pipeline": [],
                    "as": "leaked"
                }
            }],
            "cursor": {}
        }).await;
    assert!(gateway_cross_database_lookup.is_err(), "gateway admitted a cross-database $lookup");

    let gateway_database_enumeration = gateway_a.database("admin")
        .run_command(doc! { "listDatabases": 1, "authorizedDatabases": true }).await;
    assert!(gateway_database_enumeration.is_err(), "gateway admitted server database enumeration");

    // Exercise cursor continuation through OP_MSG getMore. The upstream user
    // is tenant-scoped and each frontend connection retains its own upstream
    // socket, so cursor ownership is preserved by MongoDB's authorization layer.
    {
        use futures_util::TryStreamExt;
        let collection = gateway_a.database("tenant_a_db").collection::<Document>("records");
        collection.insert_many(vec![
            doc! { "secret": "tenant-a-page-1" },
            doc! { "secret": "tenant-a-page-2" },
            doc! { "secret": "tenant-a-page-3" }
        ]).await?;
        let mut cursor = collection.find(doc! {}).batch_size(1).await?;
        let mut seen = 0usize;
        while cursor.try_next().await?.is_some() {
            seen += 1;
        }
        assert!(seen >= 4, "gateway cursor did not return all tenant A documents");
    }

    // Cleanup with the administrative identity; no tenant identity has elevated privileges.
    let _ = admin.run_command(doc! { "dropUser": "tenant_a_gateway" }).await;
    let _ = admin.run_command(doc! { "dropUser": "tenant_b_gateway" }).await;
    root.database("tenant_a_db").drop().await?;
    root.database("tenant_b_db").drop().await?;
    Ok(())
}
