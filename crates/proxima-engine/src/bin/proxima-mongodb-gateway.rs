use proxima_engine::mongodb_gateway::run_mongodb_gateway;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    run_mongodb_gateway().await?;
    Ok(())
}
