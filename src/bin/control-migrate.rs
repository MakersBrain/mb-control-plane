use mb_control_plane::Config;
use mb_control_plane::persistence::{EMBEDDED_SCHEMA_RELEASE, Store};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mb_control_plane::startup_config::validate_process("migration")?;
    Config::synthetic_data_only()?;
    let _telemetry = mb_control_plane::telemetry::init("mb-control-migrate")?;
    let store = Store::connect(&Config::database_url()?).await?;
    store.migrate().await?;
    tracing::info!(
        schema_release = EMBEDDED_SCHEMA_RELEASE,
        "control-plane database migrations complete"
    );
    Ok(())
}
