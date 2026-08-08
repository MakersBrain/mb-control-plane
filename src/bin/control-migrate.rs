use makersbrain_control_plane::Config;
use makersbrain_control_plane::persistence::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let store = Store::connect(&Config::database_url()?).await?;
    store.migrate().await?;
    tracing::info!("control-plane database migrations complete");
    Ok(())
}
