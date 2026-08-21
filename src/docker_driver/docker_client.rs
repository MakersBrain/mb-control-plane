use super::*;
use bytes::Bytes;
use futures_util::StreamExt as _;

pub(super) async fn docker_exec(
    state: &DriverState,
    container: &str,
    command: &[&str],
) -> Result<(), DriverError> {
    let response = state
        .runtime
        .client
        .post(
            state
                .runtime
                .endpoint(&format!("/containers/{container}/exec")),
        )
        .json(&json!({"AttachStdout":false,"AttachStderr":false,"Cmd":command}))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker exec create returned {}",
            response.status()
        )));
    }
    let id = response
        .json::<Value>()
        .await
        .map_err(DriverError::internal)?
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::internal("Docker exec id missing"))?
        .to_owned();
    let response = state
        .runtime
        .client
        .post(state.runtime.endpoint(&format!("/exec/{id}/start")))
        .json(&json!({"Detach":true,"Tty":false}))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker exec start returned {}",
            response.status()
        )));
    }
    for _ in 0..50 {
        let value = state
            .runtime
            .client
            .get(state.runtime.endpoint(&format!("/exec/{id}/json")))
            .send()
            .await
            .map_err(DriverError::internal)?
            .json::<Value>()
            .await
            .map_err(DriverError::internal)?;
        if value.get("Running").and_then(Value::as_bool) == Some(false) {
            return match value.get("ExitCode").and_then(Value::as_i64) {
                Some(0) => Ok(()),
                Some(code) => Err(DriverError::internal(format!(
                    "container command exited with {code}"
                ))),
                None => Err(DriverError::internal("Docker exec exit code missing")),
            };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(DriverError::internal("Docker exec timeout"))
}

pub(super) async fn docker_container_exists(
    state: &DriverState,
    name: &str,
) -> Result<bool, DriverError> {
    let response = state
        .runtime
        .client
        .get(state.runtime.endpoint(&format!("/containers/{name}/json")))
        .send()
        .await
        .map_err(DriverError::internal)?;
    match response.status() {
        StatusCode::OK => Ok(true),
        StatusCode::NOT_FOUND => Ok(false),
        status => Err(DriverError::internal(format!(
            "Docker inspect returned {status}"
        ))),
    }
}

pub(super) async fn docker_pull_image(
    state: &DriverState,
    reference: &str,
) -> Result<(), DriverError> {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("fromImage", reference)
        .finish();
    let response = state
        .runtime
        .client
        .post(state.runtime.endpoint(&format!("/images/create?{query}")))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "image pull returned {}",
            response.status()
        )));
    }
    // The engine returns a bounded progress stream. Consume it so the pull is
    // complete before any identity inspection or container creation.
    let bytes = response.bytes().await.map_err(DriverError::internal)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(DriverError::internal(
            "image pull response exceeded its bound",
        ));
    }
    Ok(())
}

pub(super) async fn docker_inspect_image(
    state: &DriverState,
    reference: &str,
) -> Result<Value, DriverError> {
    let encoded: String = url::form_urlencoded::byte_serialize(reference.as_bytes()).collect();
    let response = state
        .runtime
        .client
        .get(state.runtime.endpoint(&format!("/images/{encoded}/json")))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "image inspect returned {}",
            response.status()
        )));
    }
    response.json().await.map_err(DriverError::internal)
}

pub(super) async fn docker_inspect_container(
    state: &DriverState,
    name: &str,
) -> Result<Value, DriverError> {
    let response = state
        .runtime
        .client
        .get(state.runtime.endpoint(&format!("/containers/{name}/json")))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker inspect returned {}",
            response.status()
        )));
    }
    response.json().await.map_err(DriverError::internal)
}

pub(super) async fn docker_create_container(
    state: &DriverState,
    name: &str,
    mut body: Value,
) -> Result<(), DriverError> {
    let labels = body
        .as_object_mut()
        .ok_or_else(|| DriverError::internal("Docker container body must be an object"))?
        .entry("Labels")
        .or_insert_with(|| json!({}));
    labels
        .as_object_mut()
        .ok_or_else(|| DriverError::internal("Docker container labels must be an object"))?
        .insert(
            "mb.workspace".to_owned(),
            json!(state.config.workspace_namespace),
        );
    let response = state
        .runtime
        .client
        .post(
            state
                .runtime
                .endpoint(&format!("/containers/create?name={name}")),
        )
        .json(&body)
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        let status = response.status();
        let detail = response.text().await.unwrap_or_default();
        return Err(DriverError::internal(format!(
            "Docker create returned {status}: {detail}"
        )));
    }
    Ok(())
}

pub(super) async fn docker_start_container(
    state: &DriverState,
    name: &str,
) -> Result<(), DriverError> {
    let response = state
        .runtime
        .client
        .post(state.runtime.endpoint(&format!("/containers/{name}/start")))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() && response.status() != StatusCode::NOT_MODIFIED {
        return Err(DriverError::internal(format!(
            "Docker start returned {}",
            response.status()
        )));
    }
    Ok(())
}

pub(super) async fn docker_stop_container(
    state: &DriverState,
    name: &str,
) -> Result<(), DriverError> {
    let response = state
        .runtime
        .client
        .post(
            state
                .runtime
                .endpoint(&format!("/containers/{name}/stop?t=30")),
        )
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() && response.status() != StatusCode::NOT_MODIFIED {
        return Err(DriverError::internal(format!(
            "Docker stop returned {}",
            response.status()
        )));
    }
    Ok(())
}

pub(super) async fn docker_signal_container(
    state: &DriverState,
    name: &str,
    signal: &str,
) -> Result<(), DriverError> {
    let response = state
        .runtime
        .client
        .post(
            state
                .runtime
                .endpoint(&format!("/containers/{name}/kill?signal={signal}")),
        )
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "{} signal returned {}",
            state.runtime.kind.name(),
            response.status()
        )));
    }
    Ok(())
}

pub(super) async fn docker_wait_container(
    state: &DriverState,
    name: &str,
) -> Result<i64, DriverError> {
    let response = state
        .runtime
        .client
        .post(
            state
                .runtime
                .endpoint(&format!("/containers/{name}/wait?condition=not-running")),
        )
        .send()
        .await
        .map_err(DriverError::internal)?;
    let value: Value = response.json().await.map_err(DriverError::internal)?;
    value
        .get("StatusCode")
        .and_then(Value::as_i64)
        .ok_or_else(|| DriverError::internal("Docker wait response missing status"))
}

pub(super) async fn docker_delete_container(
    state: &DriverState,
    name: &str,
) -> Result<(), DriverError> {
    let response = state
        .runtime
        .client
        .delete(
            state
                .runtime
                .endpoint(&format!("/containers/{name}?force=true")),
        )
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() && response.status() != StatusCode::NOT_FOUND {
        return Err(DriverError::internal(format!(
            "Docker delete returned {}",
            response.status()
        )));
    }
    Ok(())
}

pub(super) async fn docker_create_volume(
    state: &DriverState,
    name: &str,
) -> Result<(), DriverError> {
    let response = state
        .runtime
        .client
        .post(state.runtime.endpoint("/volumes/create"))
        .json(&json!({"Name":name,"Labels":{"mb.kind":"paperless-volume","mb.workspace":state.config.workspace_namespace}}))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker volume create returned {}",
            response.status()
        )));
    }
    Ok(())
}

pub(super) async fn docker_volume_exists(
    state: &DriverState,
    name: &str,
) -> Result<bool, DriverError> {
    let response = state
        .runtime
        .client
        .get(state.runtime.endpoint(&format!("/volumes/{name}")))
        .send()
        .await
        .map_err(DriverError::internal)?;
    match response.status() {
        StatusCode::OK => Ok(true),
        StatusCode::NOT_FOUND => Ok(false),
        status => Err(DriverError::internal(format!(
            "volume inspect returned {status}"
        ))),
    }
}

pub(super) async fn docker_create_extension_volume(
    state: &DriverState,
    name: &str,
    manifest_digest: &str,
    payload_digest: &str,
) -> Result<(), DriverError> {
    let response = state.runtime.client.post(state.runtime.endpoint("/volumes/create"))
        .json(&json!({"Name":name,"Labels":{"mb.kind":"odoo-extension","mb.workspace":state.config.workspace_namespace,"mb.extension-manifest":manifest_digest,"mb.payload":payload_digest}}))
        .send().await.map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "extension volume create returned {}",
            response.status()
        )));
    }
    Ok(())
}

pub(super) async fn docker_delete_extension_volume(
    state: &DriverState,
    name: &str,
) -> Result<bool, DriverError> {
    let response = state
        .runtime
        .client
        .delete(state.runtime.endpoint(&format!("/volumes/{name}")))
        .send()
        .await
        .map_err(DriverError::internal)?;
    match response.status() {
        StatusCode::NO_CONTENT => Ok(true),
        StatusCode::NOT_FOUND => Ok(false),
        StatusCode::CONFLICT => Err(DriverError::bad(
            "extension volume is still referenced by an engine mount",
        )),
        status => Err(DriverError::internal(format!(
            "extension volume delete returned {status}"
        ))),
    }
}

pub(super) async fn docker_get_archive_bounded(
    state: &DriverState,
    container: &str,
    path: &str,
    maximum: usize,
) -> Result<Bytes, DriverError> {
    if !path.starts_with('/')
        || path.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        })
    {
        return Err(DriverError::internal("unsafe archive path"));
    }
    let response = state
        .runtime
        .client
        .get(
            state
                .runtime
                .endpoint(&format!("/containers/{container}/archive?path={path}")),
        )
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(
            "extension payload archive is unavailable",
        ));
    }
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(DriverError::bad(
            "extension payload exceeds the extraction byte limit",
        ));
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(DriverError::internal)?;
        if bytes.len().saturating_add(chunk.len()) > maximum {
            return Err(DriverError::bad(
                "extension payload exceeds the extraction byte limit",
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(bytes))
}

pub(super) async fn docker_put_archive(
    state: &DriverState,
    container: &str,
    path: &str,
    archive: Bytes,
) -> Result<(), DriverError> {
    if !path.starts_with('/')
        || path.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'))
        })
    {
        return Err(DriverError::internal("unsafe archive path"));
    }
    let response = state
        .runtime
        .client
        .put(state.runtime.endpoint(&format!(
            "/containers/{container}/archive?path={path}&noOverwriteDirNonDir=true"
        )))
        .header(reqwest::header::CONTENT_TYPE, "application/x-tar")
        .body(archive)
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "extension archive extraction returned {}",
            response.status()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_uses_the_supported_compatibility_api() {
        assert_eq!(ContainerRuntimeKind::Docker.api_version(), "v1.47");
        assert_eq!(ContainerRuntimeKind::Podman.api_version(), "v1.40");
    }

    #[test]
    fn runtime_kind_is_closed() {
        assert_eq!(
            ContainerRuntimeKind::parse("docker").unwrap(),
            ContainerRuntimeKind::Docker
        );
        assert_eq!(
            ContainerRuntimeKind::parse("podman").unwrap(),
            ContainerRuntimeKind::Podman
        );
        assert!(ContainerRuntimeKind::parse("containerd").is_err());
    }
}
