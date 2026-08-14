use makersbrain_control_plane::api::AppState;
use makersbrain_control_plane::auth::Authenticator;
use makersbrain_control_plane::invitation::InvitationVerifier;
use makersbrain_control_plane::persistence::Store;
use makersbrain_control_plane::{Config, app, shutdown_signal};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    makersbrain_control_plane::startup_config::validate_process("api")?;
    let _telemetry = makersbrain_control_plane::telemetry::init("makersbrain-control-api")?;
    let config = Config::from_env()?;
    makersbrain_control_plane::validate_privacy_export_configuration()?;
    let store = Store::connect(&config.database_url).await?;
    let auth = std::sync::Arc::new(Authenticator::new(
        config.oidc_issuer.clone(),
        config.oidc_audience.clone(),
        config.oidc_discovery_url.clone(),
    )?);
    auth.warm().await?;
    let invitation_verifier = std::sync::Arc::new(InvitationVerifier::from_json_file(
        &config.invitation_verification_keys_file,
    )?);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(address = %config.listen, "control API listening");
    axum::serve(
        listener,
        app(AppState {
            store,
            config,
            auth,
            invitation_verifier,
        }),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}
