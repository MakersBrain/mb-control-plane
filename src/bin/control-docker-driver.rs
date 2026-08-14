use makersbrain_control_plane::docker_driver::{DockerDriverConfig, app};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    makersbrain_control_plane::startup_config::validate_process("docker_driver")?;
    let _telemetry = makersbrain_control_plane::telemetry::init("makersbrain-docker-driver")?;
    let config = DockerDriverConfig::from_env()?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address = %config.listen, "Docker deployment driver listening");
    axum::serve(listener, app(config).await?)
        .with_graceful_shutdown(makersbrain_control_plane::shutdown_signal())
        .await?;
    Ok(())
}
