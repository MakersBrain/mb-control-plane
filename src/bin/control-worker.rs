use std::process::ExitCode;

use mb_control_plane::persistence::Store;
use mb_control_plane::worker_config::WorkerConfig;

fn startup_failure(service: &'static str, error_class: &'static str) -> ExitCode {
    eprintln!(
        "{{\"level\":\"ERROR\",\"service\":\"{service}\",\"error_class\":\"{error_class}\",\"message\":\"process startup failed\"}}"
    );
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    let Some(queue) = std::env::args().nth(1) else {
        return startup_failure("mb-control-worker", "queue_argument_missing");
    };
    let (service_name, process) = match queue.as_str() {
        "tenant-provisioning" => ("mb-worker-provisioning", "provisioning_worker"),
        "membership-provisioning" => ("mb-worker-membership", "membership_worker"),
        "invoice-capture" => ("mb-worker-invoice", "invoice_worker"),
        "inventory-capture" => ("mb-worker-inventory", "inventory_worker"),
        "email-delivery" => ("mb-worker-email", "email_worker"),
        "tenant-reconciliation" => ("mb-worker-reconciliation", "reconciliation_worker"),
        "tenant-lifecycle" => ("mb-worker-lifecycle", "lifecycle_worker"),
        "release-adoption" => ("mb-worker-release", "release_worker"),
        "privacy-operations" => ("mb-worker-privacy", "privacy_worker"),
        _ => return startup_failure("mb-control-worker", "queue_argument_invalid"),
    };
    if mb_control_plane::startup_config::validate_process(process).is_err() {
        return startup_failure(service_name, "startup_contract_invalid");
    }
    let config = match WorkerConfig::from_env(&queue) {
        Ok(config) => config,
        Err(_) => return startup_failure(service_name, "configuration_invalid"),
    };
    let _telemetry = match mb_control_plane::telemetry::init(service_name) {
        Ok(telemetry) => telemetry,
        Err(_) => return startup_failure(service_name, "telemetry_initialization_failed"),
    };
    let store = match Store::connect(config.database_url()).await {
        Ok(store) => store,
        Err(error) => {
            let (error_classes, error_chain_truncated) =
                mb_control_plane::error_reporting::safe_anyhow_chain(&error);
            tracing::error!(
                ?error_classes,
                error_chain_truncated,
                "worker database connection failed"
            );
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = mb_control_plane::worker::run(store, &queue, config).await {
        let (error_classes, error_chain_truncated) =
            mb_control_plane::error_reporting::safe_anyhow_chain(&error);
        tracing::error!(
            ?error_classes,
            error_chain_truncated,
            "worker stopped unexpectedly"
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
