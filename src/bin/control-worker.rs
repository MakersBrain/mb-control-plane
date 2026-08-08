use makersbrain_control_plane::Config;
use makersbrain_control_plane::persistence::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let queue = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: control-worker <queue>"))?;
    let database_url = Config::database_url()?;
    let store = Store::connect(&database_url).await?;
    makersbrain_control_plane::worker::run(store, &queue).await
}
