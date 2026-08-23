use std::os::fd::{FromRawFd, RawFd};
use std::process::ExitCode;

use mb_control_plane::docker_driver::{DockerDriverConfig, DriverListen, build_application};

fn startup_failure(error_class: &'static str) -> ExitCode {
    eprintln!(
        "{{\"level\":\"ERROR\",\"service\":\"mb-container-driver\",\"error_class\":\"{error_class}\",\"message\":\"process startup failed\"}}"
    );
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    if mb_control_plane::startup_config::validate_process("docker_driver").is_err() {
        return startup_failure("startup_contract_invalid");
    }
    let config = match DockerDriverConfig::from_env() {
        Ok(config) => config,
        Err(_) => return startup_failure("configuration_invalid"),
    };
    let _telemetry = match mb_control_plane::telemetry::init("mb-container-driver") {
        Ok(telemetry) => telemetry,
        Err(_) => return startup_failure("telemetry_initialization_failed"),
    };
    match config.listen.clone() {
        DriverListen::Tcp(address) => {
            let listener = match tokio::net::TcpListener::bind(address).await {
                Ok(listener) => listener,
                Err(error) => {
                    tracing::error!(
                        error_class = mb_control_plane::error_reporting::safe_error_class(&error),
                        "container driver listener bind failed"
                    );
                    return ExitCode::FAILURE;
                }
            };
            tracing::info!(%address, "container deployment driver listening");
            let application = match build_application(config).await {
                Ok(application) => application,
                Err(error) => {
                    let (error_classes, error_chain_truncated) =
                        mb_control_plane::error_reporting::safe_anyhow_chain(&error);
                    tracing::error!(
                        ?error_classes,
                        error_chain_truncated,
                        "container driver state initialization failed"
                    );
                    return ExitCode::FAILURE;
                }
            };
            let (router, lifecycle) = application.into_parts();
            let signal_lifecycle = lifecycle.clone();
            let server_result = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    mb_control_plane::shutdown_signal().await;
                    signal_lifecycle.begin_draining();
                })
                .await;
            lifecycle.begin_draining();
            let lifecycle_result = lifecycle.shutdown().await;
            if server_result.is_err() {
                tracing::error!(
                    error_class = "server_failed",
                    "container driver stopped unexpectedly"
                );
            }
            if lifecycle_result.is_err() {
                tracing::error!(
                    error_class = "driver_task_drain_failed",
                    "container driver task drain failed"
                );
            }
            if server_result.is_err() || lifecycle_result.is_err() {
                return ExitCode::FAILURE;
            }
        }
        DriverListen::SystemdUnix(path) => {
            let listener = match systemd_unix_listener(&path) {
                Ok(listener) => listener,
                Err(error) => {
                    let (error_classes, error_chain_truncated) =
                        mb_control_plane::error_reporting::safe_anyhow_chain(&error);
                    tracing::error!(
                        ?error_classes,
                        error_chain_truncated,
                        "container driver socket activation failed"
                    );
                    return ExitCode::FAILURE;
                }
            };
            tracing::info!(
                listen_transport = "systemd_unix",
                "native deployment driver listening"
            );
            let application = match build_application(config).await {
                Ok(application) => application,
                Err(error) => {
                    let (error_classes, error_chain_truncated) =
                        mb_control_plane::error_reporting::safe_anyhow_chain(&error);
                    tracing::error!(
                        ?error_classes,
                        error_chain_truncated,
                        "container driver state initialization failed"
                    );
                    return ExitCode::FAILURE;
                }
            };
            let (router, lifecycle) = application.into_parts();
            let signal_lifecycle = lifecycle.clone();
            let server_result = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    mb_control_plane::shutdown_signal().await;
                    signal_lifecycle.begin_draining();
                })
                .await;
            lifecycle.begin_draining();
            let lifecycle_result = lifecycle.shutdown().await;
            if server_result.is_err() {
                tracing::error!(
                    error_class = "server_failed",
                    "container driver stopped unexpectedly"
                );
            }
            if lifecycle_result.is_err() {
                tracing::error!(
                    error_class = "driver_task_drain_failed",
                    "container driver task drain failed"
                );
            }
            if server_result.is_err() || lifecycle_result.is_err() {
                return ExitCode::FAILURE;
            }
        }
    }
    ExitCode::SUCCESS
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
