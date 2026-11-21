use proxima_engine::redis_gateway::run_redis_gateway;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    run_redis_gateway().await?;
    Ok(())
}
