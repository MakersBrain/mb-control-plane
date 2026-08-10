use makersbrain_control_plane::extraction_broker::{BrokerState, app};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let listen = std::env::var("BROKER_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, app(BrokerState::from_env()?))
        .with_graceful_shutdown(makersbrain_control_plane::shutdown_signal())
        .await?;
    Ok(())
}
