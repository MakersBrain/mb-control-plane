use std::os::fd::{FromRawFd, RawFd};

use mb_control_plane::docker_driver::{DockerDriverConfig, DriverListen, app};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mb_control_plane::startup_config::validate_process("docker_driver")?;
    let _telemetry = mb_control_plane::telemetry::init("mb-container-driver")?;
    let config = DockerDriverConfig::from_env()?;
    match config.listen.clone() {
        DriverListen::Tcp(address) => {
            let listener = tokio::net::TcpListener::bind(address).await?;
            tracing::info!(%address, "container deployment driver listening");
            axum::serve(listener, app(config).await?)
                .with_graceful_shutdown(mb_control_plane::shutdown_signal())
                .await?;
        }
        DriverListen::SystemdUnix(path) => {
            let listener = systemd_unix_listener(&path)?;
            tracing::info!(socket=%path.display(), "native deployment driver listening");
            axum::serve(listener, app(config).await?)
                .with_graceful_shutdown(mb_control_plane::shutdown_signal())
                .await?;
        }
    }
    Ok(())
}

fn systemd_unix_listener(path: &std::path::Path) -> anyhow::Result<tokio::net::UnixListener> {
    let activated = std::env::var("LISTEN_PID").ok().as_deref()
        == Some(std::process::id().to_string().as_str())
        && std::env::var("LISTEN_FDS").ok().as_deref() == Some("1");
    if activated {
        // SAFETY: systemd's socket-activation ABI assigns the first and only
        // declared descriptor to fd 3. The PID and descriptor count above bind
        // ownership to this process before it is converted exactly once.
        let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3 as RawFd) };
        listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener)?;
        if listener.local_addr()?.as_pathname() != Some(path) {
            anyhow::bail!("the activated driver socket path differs from DRIVER_UNIX_SOCKET");
        }
        return Ok(listener);
    }
    anyhow::bail!("the native deployment driver requires exactly one systemd-activated socket")
}
