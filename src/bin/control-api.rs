use makersbrain_control_plane::api::AppState;
use makersbrain_control_plane::auth::Authenticator;
use makersbrain_control_plane::persistence::Store;
use makersbrain_control_plane::{Config, app, shutdown_signal};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Config::from_env()?;
    let store = Store::connect(&config.database_url).await?;
    let auth = std::sync::Arc::new(Authenticator::new(
        config.oidc_issuer.clone(),
        config.oidc_audience.clone(),
        config.oidc_discovery_url.clone(),
    )?);
    auth.warm().await?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address = %config.listen, "control API listening");
    axum::serve(
        listener,
        app(AppState {
            store,
            config,
            auth,
        }),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}
