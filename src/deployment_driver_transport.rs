use std::path::Path;
use std::time::Duration;

pub fn client(
    token: Option<&str>,
    timeout: Duration,
    socket: Option<&Path>,
) -> anyhow::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if let Some(socket) = socket {
        if !socket.is_absolute() {
            anyhow::bail!("CONTROL_DEPLOYMENT_DRIVER_SOCKET must be absolute");
        }
        builder = builder.unix_socket(socket);
    }
    if let Some(token) = token {
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        value.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, value);
        builder = builder.default_headers(headers);
    }
    Ok(builder.build()?)
}

pub fn configured_socket() -> anyhow::Result<Option<std::path::PathBuf>> {
    let socket = crate::runtime_secret::configuration("CONTROL_DEPLOYMENT_DRIVER_SOCKET")
        .map_err(anyhow::Error::msg)?
        .filter(|value| !value.trim().is_empty())
        .map(std::path::PathBuf::from);
    if socket.as_ref().is_some_and(|path| !path.is_absolute()) {
        anyhow::bail!("CONTROL_DEPLOYMENT_DRIVER_SOCKET must be absolute");
    }
    Ok(socket)
}
