use mb_control_plane::mail_gateway::{MailGatewayState, app};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    mb_control_plane::startup_config::validate_process("mail_gateway")?;
    let _telemetry = mb_control_plane::telemetry::init("mb-mail-gateway")?;
    let state = MailGatewayState::from_env()?;
    let listen = state.listen;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, app(state))
        .with_graceful_shutdown(mb_control_plane::shutdown_signal())
        .await?;
    Ok(())
}
