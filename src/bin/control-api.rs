use std::process::ExitCode;

use mb_control_plane::api::AppState;
use mb_control_plane::auth::Authenticator;
use mb_control_plane::invitation::InvitationVerifier;
use mb_control_plane::persistence::{Store, TenantStore};
use mb_control_plane::{Config, app, shutdown_signal};

fn startup_failure(error_class: &'static str) -> ExitCode {
    eprintln!(
        "{{\"level\":\"ERROR\",\"service\":\"mb-control-api\",\"error_class\":\"{error_class}\",\"message\":\"process startup failed\"}}"
    );
    ExitCode::FAILURE
}

#[tokio::main]
async fn main() -> ExitCode {
    if mb_control_plane::startup_config::validate_process("api").is_err() {
        return startup_failure("startup_contract_invalid");
    }
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(_) => return startup_failure("configuration_invalid"),
    };
    if mb_control_plane::validate_privacy_export_configuration().is_err() {
        return startup_failure("privacy_export_configuration_invalid");
    }
    let _telemetry = match mb_control_plane::telemetry::init("mb-control-api") {
        Ok(telemetry) => telemetry,
        Err(_) => return startup_failure("telemetry_initialization_failed"),
    };
    let store = match Store::connect(&config.database_url).await {
        Ok(store) => store,
        Err(error) => {
            let (error_classes, error_chain_truncated) =
                mb_control_plane::error_reporting::safe_anyhow_chain(&error);
            tracing::error!(
                ?error_classes,
                error_chain_truncated,
                "control API database connection failed"
            );
            return ExitCode::FAILURE;
        }
    };
    let tenant_store = match TenantStore::connect(&config.tenant_database_url).await {
        Ok(store) => store,
        Err(error) => {
            let (error_classes, error_chain_truncated) =
                mb_control_plane::error_reporting::safe_anyhow_chain(&error);
            tracing::error!(
                ?error_classes,
                error_chain_truncated,
                database_scope = "workshop",
                "control API database connection failed"
            );
            return ExitCode::FAILURE;
        }
    };
    let auth = match Authenticator::new(
        config.oidc_issuer.clone(),
        config.oidc_audience.clone(),
        config.oidc_discovery_url.clone(),
    ) {
        Ok(auth) => std::sync::Arc::new(auth),
        Err(_) => {
            tracing::error!(
                error_class = "oidc_client_invalid",
                "control API startup failed"
            );
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = auth.warm().await {
        let (error_classes, error_chain_truncated) =
            mb_control_plane::error_reporting::safe_anyhow_chain(&error);
        tracing::error!(
            ?error_classes,
            error_chain_truncated,
            "OIDC discovery warmup failed"
        );
        return ExitCode::FAILURE;
    }
    let invitation_verifier =
        match InvitationVerifier::from_json_file(&config.invitation_verification_keys_file) {
            Ok(verifier) => std::sync::Arc::new(verifier),
            Err(_) => {
                tracing::error!(
                    error_class = "invitation_verification_keys_invalid",
                    "control API startup failed"
                );
                return ExitCode::FAILURE;
            }
        };
    let listener = match tokio::net::TcpListener::bind(config.listen).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(
                error_class = mb_control_plane::error_reporting::safe_error_class(&error),
                "control API listener bind failed"
            );
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(address = %config.listen, "control API listening");
    let state = match AppState::new(store, tenant_store, config, auth, invitation_verifier) {
        Ok(state) => state,
        Err(error) => {
            let (error_classes, error_chain_truncated) =
                mb_control_plane::error_reporting::safe_anyhow_chain(&error);
            tracing::error!(
                ?error_classes,
                error_chain_truncated,
                "control API state initialization failed"
            );
            return ExitCode::FAILURE;
        }
    };
    if axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .is_err()
    {
        tracing::error!(
            error_class = "server_failed",
            "control API stopped unexpectedly"
        );
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
