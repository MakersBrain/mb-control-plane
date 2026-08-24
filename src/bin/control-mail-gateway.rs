use std::process::ExitCode;

use mb_control_plane::mail_gateway::{MailGatewayState, app};

fn startup_failure(error_class: &'static str) -> ExitCode {
    // Configuration is deliberately validated before telemetry is initialized.
    // Emit a bounded machine-readable fallback without formatting the source
    // error, which may contain secret values or filesystem paths.
    eprintln!(
        "{{\"level\":\"ERROR\",\"service\":\"mb-mail-gateway\",\"error_class\":\"{error_class}\",\"message\":\"process startup failed\"}}"
    );
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    if mb_control_plane::startup_config::validate_process("mail_gateway").is_err() {
        return startup_failure("startup_contract_invalid");
    }
    let state = match MailGatewayState::from_env() {
        Ok(state) => state,
        Err(_) => return startup_failure("configuration_invalid"),
    };
    let _telemetry = match mb_control_plane::telemetry::init("mb-mail-gateway") {
        Ok(telemetry) => telemetry,
        Err(_) => return startup_failure("telemetry_initialization_failed"),
    };
    let listen = state.listen;
    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(listener) => listener,
        Err(_) => {
            tracing::error!(
                error_class = "listener_bind_failed",
                "mail gateway startup failed"
            );
            return ExitCode::FAILURE;
        }
    };
    if axum::serve(listener, app(state))
        .with_graceful_shutdown(mb_control_plane::shutdown_signal())
        .await
        .is_err()
    {
        tracing::error!(
            error_class = "server_failed",
            "mail gateway stopped unexpectedly"
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
