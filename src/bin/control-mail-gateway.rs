use makersbrain_control_plane::mail_gateway::{MailGatewayState, app};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    makersbrain_control_plane::startup_config::validate_process("mail_gateway")?;
    let _telemetry = makersbrain_control_plane::telemetry::init("makersbrain-mail-gateway")?;
    let state = MailGatewayState::from_env()?;
    let listen = state.listen;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app(state))
        .with_graceful_shutdown(makersbrain_control_plane::shutdown_signal())
        .await?;
    Ok(())
}
