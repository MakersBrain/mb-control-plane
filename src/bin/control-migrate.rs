use std::process::ExitCode;

use mb_control_plane::config::MigrationConfig;
use mb_control_plane::persistence::{EMBEDDED_SCHEMA_RELEASE, Store};

fn startup_failure(error_class: &'static str) -> ExitCode {
    eprintln!(
        "{{\"level\":\"ERROR\",\"service\":\"mb-control-migrate\",\"error_class\":\"{error_class}\",\"message\":\"process startup failed\"}}"
    );
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    if mb_control_plane::startup_config::validate_process("migration").is_err() {
        return startup_failure("startup_contract_invalid");
    }
    let config = match MigrationConfig::from_env() {
        Ok(config) => config,
        Err(_) => return startup_failure("configuration_invalid"),
    };
    let _telemetry = match mb_control_plane::telemetry::init("mb-control-migrate") {
        Ok(telemetry) => telemetry,
        Err(_) => return startup_failure("telemetry_initialization_failed"),
    };
    tracing::debug!(
        synthetic_data_only = config.synthetic_data_only(),
        "migration configuration validated"
    );
    let store = match Store::connect(config.database_url()).await {
        Ok(store) => store,
        Err(error) => {
            let (error_classes, error_chain_truncated) =
                mb_control_plane::error_reporting::safe_anyhow_chain(&error);
            tracing::error!(
                ?error_classes,
                error_chain_truncated,
                "migration database connection failed"
            );
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = store.migrate().await {
        let (error_classes, error_chain_truncated) =
            mb_control_plane::error_reporting::safe_anyhow_chain(&error);
        tracing::error!(
            ?error_classes,
            error_chain_truncated,
            "database migration failed"
        );
        return ExitCode::FAILURE;
    }
    tracing::info!(
        schema_release = EMBEDDED_SCHEMA_RELEASE,
        "control-plane database migrations complete"
    );
    ExitCode::SUCCESS
}
