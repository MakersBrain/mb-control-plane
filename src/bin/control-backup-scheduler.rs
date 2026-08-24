use std::process::ExitCode;

use mb_control_plane::backup_scheduler::BackupScheduler;
use mb_control_plane::backup_scheduler_config::BackupSchedulerConfig;

fn startup_failure(error_class: &'static str) -> ExitCode {
    eprintln!(
        "{{\"level\":\"ERROR\",\"service\":\"mb-backup-scheduler\",\"error_class\":\"{error_class}\",\"message\":\"process startup failed\"}}"
    );
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    if mb_control_plane::startup_config::validate_process("backup_scheduler").is_err() {
        return startup_failure("startup_contract_invalid");
    }
    let config = match BackupSchedulerConfig::from_env() {
        Ok(config) => config,
        Err(_) => return startup_failure("configuration_invalid"),
    };
    let _telemetry = match mb_control_plane::telemetry::init("mb-backup-scheduler") {
        Ok(telemetry) => telemetry,
        Err(_) => return startup_failure("telemetry_initialization_failed"),
    };
    tracing::info!(
        release_id = config.release_id(),
        "backup scheduler starting"
    );
    let scheduler = match BackupScheduler::connect(&config).await {
        Ok(scheduler) => scheduler,
        Err(error) => {
            let (error_classes, error_chain_truncated) =
                mb_control_plane::error_reporting::safe_anyhow_chain(&error);
            tracing::error!(
                ?error_classes,
                error_chain_truncated,
                "backup scheduler initialization failed"
            );
            return ExitCode::FAILURE;
        }
    };
    if !config.enabled() {
        tracing::info!("nightly workshop backup scheduling is disabled");
    }
    loop {
        if config.enabled()
            && let Err(error) = scheduler.schedule_due_backups().await
        {
            let (error_classes, error_chain_truncated) =
                mb_control_plane::error_reporting::safe_anyhow_chain(&error);
            tracing::error!(
                ?error_classes,
                error_chain_truncated,
                "nightly backup scheduling failed"
            );
        }
        if config.enabled()
            && let Err(error) = scheduler.rehearse_due_recoveries().await
        {
            let (error_classes, error_chain_truncated) =
                mb_control_plane::error_reporting::safe_anyhow_chain(&error);
            tracing::error!(
                ?error_classes,
                error_chain_truncated,
                "monthly recovery rehearsal scheduling failed"
            );
        }
        tokio::select! {
            _ = tokio::time::sleep(config.interval()) => {},
            _ = mb_control_plane::shutdown_signal() => break,
        }
    }
    ExitCode::SUCCESS
}
