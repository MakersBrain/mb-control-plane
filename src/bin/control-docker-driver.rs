use mb_control_plane::docker_driver::{DockerDriverConfig, DriverListen, app};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mb_control_plane::startup_config::validate_process("docker_driver")?;
    let _telemetry = mb_control_plane::telemetry::init("mb-docker-driver")?;
    let config = DockerDriverConfig::from_env()?;
    let address = match config.listen.clone() {
        DriverListen::Tcp(address) => address,
        DriverListen::SystemdUnix(_) => anyhow::bail!("control-docker-driver requires TCP"),
    };
    let listener = tokio::net::TcpListener::bind(address).await?;
    tracing::info!(%address, "Docker deployment driver listening");
    axum::serve(listener, app(config).await?)
        .with_graceful_shutdown(mb_control_plane::shutdown_signal())
        .await?;
    Ok(())
}
