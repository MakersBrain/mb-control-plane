pub mod api;
pub mod api_error;
pub mod auth;
pub mod backup_scheduler;
pub mod backup_scheduler_config;
pub mod command;
pub mod config;
pub mod deployment_driver_transport;
pub mod docker_driver;
pub mod domain;
pub mod error_reporting;
pub mod extraction_broker;
pub mod integrations;
pub mod inventory_label;
pub mod invitation;
pub mod invoice;
pub mod mail_gateway;
pub mod modules;
pub mod openapi;
pub(crate) mod outbound_http;
pub mod persistence;
pub(crate) mod privacy_crypto;
pub mod release;
pub mod runtime_secret;
pub mod startup_config;
pub mod telemetry;
pub mod worker;
pub mod worker_config;
pub(crate) mod workers;

pub use api::app;
pub use config::Config;

pub fn validate_privacy_export_configuration() -> anyhow::Result<()> {
    privacy_crypto::validate_export_configuration()
        .map_err(|_| anyhow::anyhow!("privacy export encryption is not configured"))
}

pub async fn shutdown_signal() {
    let interrupt = async {
        tokio::signal::ctrl_c()
            .await
            .expect("installing Ctrl-C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = interrupt => tracing::info!("interrupt received"),
        _ = terminate => tracing::info!("termination requested"),
    }
}
