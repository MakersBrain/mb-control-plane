use std::process::ExitCode;

use mb_control_plane::extraction_broker::{BrokerConfig, BrokerState, app};

fn startup_failure(error_class: &'static str) -> ExitCode {
    // The telemetry subscriber is unavailable during early validation. Keep
    // the fallback structured and bounded, and never format the source error.
    eprintln!(
        "{{\"level\":\"ERROR\",\"service\":\"mb-document-extraction-broker\",\"error_class\":\"{error_class}\",\"message\":\"process startup failed\"}}"
    );
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    if mb_control_plane::startup_config::validate_process("document_extraction_broker").is_err() {
        return startup_failure("startup_contract_invalid");
    }
    let config = match BrokerConfig::from_env() {
        Ok(config) => config,
        Err(_) => return startup_failure("configuration_invalid"),
    };
    let _telemetry = match mb_control_plane::telemetry::init("mb-document-extraction-broker") {
        Ok(telemetry) => telemetry,
        Err(_) => return startup_failure("telemetry_initialization_failed"),
    };
    let listener = match tokio::net::TcpListener::bind(config.listen).await {
        Ok(listener) => listener,
        Err(_) => {
            tracing::error!(
                error_class = "listener_bind_failed",
                "document extraction broker startup failed"
            );
            return ExitCode::FAILURE;
        }
    };
    if axum::serve(listener, app(BrokerState::from(config)))
        .with_graceful_shutdown(mb_control_plane::shutdown_signal())
        .await
        .is_err()
    {
        tracing::error!(
            error_class = "server_failed",
            "document extraction broker stopped unexpectedly"
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
