use std::process::ExitCode;

use mb_control_plane::docker_driver::{DockerDriverConfig, DriverListen, build_application};

fn startup_failure(error_class: &'static str) -> ExitCode {
    eprintln!(
        "{{\"level\":\"ERROR\",\"service\":\"mb-docker-driver\",\"error_class\":\"{error_class}\",\"message\":\"process startup failed\"}}"
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
    let _telemetry = match mb_control_plane::telemetry::init("mb-docker-driver") {
        Ok(telemetry) => telemetry,
        Err(_) => return startup_failure("telemetry_initialization_failed"),
    };
    let address = match config.listen.clone() {
        DriverListen::Tcp(address) => address,
        DriverListen::SystemdUnix(_) => {
            tracing::error!(
                error_class = "listen_transport_invalid",
                "Docker driver startup failed"
            );
            return ExitCode::FAILURE;
        }
    };
    let listener = match tokio::net::TcpListener::bind(address).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(
                error_class = mb_control_plane::error_reporting::safe_error_class(&error),
                "Docker driver listener bind failed"
            );
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(%address, "Docker deployment driver listening");
    let application = match build_application(config).await {
        Ok(application) => application,
        Err(error) => {
            let (error_classes, error_chain_truncated) =
                mb_control_plane::error_reporting::safe_anyhow_chain(&error);
            tracing::error!(
                ?error_classes,
                error_chain_truncated,
                "Docker driver state initialization failed"
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
            "Docker driver stopped unexpectedly"
        );
    }
    if lifecycle_result.is_err() {
        tracing::error!(
            error_class = "driver_task_drain_failed",
            "Docker driver task drain failed"
        );
    }
    if server_result.is_ok() && lifecycle_result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
