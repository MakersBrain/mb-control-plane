use makersbrain_control_plane::Config;
use makersbrain_control_plane::persistence::{EMBEDDED_SCHEMA_RELEASE, Store};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    makersbrain_control_plane::startup_config::validate_process("migration")?;
    Config::synthetic_data_only()?;
    let _telemetry = makersbrain_control_plane::telemetry::init("makersbrain-control-migrate")?;
    let store = Store::connect(&Config::database_url()?).await?;
    store.migrate().await?;
    tracing::info!(
        schema_release = EMBEDDED_SCHEMA_RELEASE,
        "control-plane database migrations complete"
    );
    Ok(())
}
