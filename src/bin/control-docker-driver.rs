use mb_control_plane::docker_driver::{DockerDriverConfig, app};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mb_control_plane::startup_config::validate_process("docker_driver")?;
    let _telemetry = mb_control_plane::telemetry::init("mb-docker-driver")?;
    let config = DockerDriverConfig::from_env()?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address = %config.listen, "container deployment driver listening");
    axum::serve(listener, app(config).await?)
        .with_graceful_shutdown(mb_control_plane::shutdown_signal())
        .await?;
    Ok(())
}
