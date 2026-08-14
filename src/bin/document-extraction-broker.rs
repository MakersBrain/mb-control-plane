use makersbrain_control_plane::extraction_broker::{BrokerState, app};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    makersbrain_control_plane::startup_config::validate_process("document_extraction_broker")?;
    let _telemetry =
        makersbrain_control_plane::telemetry::init("makersbrain-document-extraction-broker")?;
    let listen = std::env::var("BROKER_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, app(BrokerState::from_env()?))
        .with_graceful_shutdown(makersbrain_control_plane::shutdown_signal())
        .await?;
    Ok(())
}
