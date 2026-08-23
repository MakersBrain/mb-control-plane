use std::path::Path;
use std::time::Duration;

use crate::outbound_http::TraceRequestBuilderExt as _;

pub fn client(timeout: Duration, socket: Option<&Path>) -> anyhow::Result<reqwest::Client> {
    let mut builder =
        crate::outbound_http::internal_service_builder("mb-control-plane/deployment-driver")
            .timeout(timeout);
    if let Some(socket) = socket {
        if !socket.is_absolute() {
            anyhow::bail!("CONTROL_DEPLOYMENT_DRIVER_SOCKET must be absolute");
        }
        builder = builder.unix_socket(socket);
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

/// Adds request-local trace context to an authenticated deployment-driver call.
///
/// The client can use a Unix socket, but the request still crosses the durable
/// control-plane/driver boundary and is safe to correlate. Docker Engine API
/// requests use a different client and deliberately do not receive this header.
pub fn traced(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    request.with_current_trace_context()
}
