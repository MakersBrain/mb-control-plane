use std::collections::BTreeSet;

use super::*;
use bytes::Bytes;
use futures_util::StreamExt as _;

// Docker Engine calls may use a Unix socket and are local runtime-control
// protocol messages rather than service-to-service HTTP. They deliberately do
// not receive W3C headers; operation IDs already correlate runtime mutations.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DockerRestartPolicy {
    No,
    UnlessStopped,
}

impl DockerRestartPolicy {
    fn name(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::UnlessStopped => "unless-stopped",
        }
    }
}

fn apply_restart_policy(body: &mut Value, policy: DockerRestartPolicy) -> Result<(), DriverError> {
    let host = body
        .as_object_mut()
        .ok_or_else(|| DriverError::internal("Docker container body must be an object"))?
        .entry("HostConfig")
        .or_insert_with(|| json!({}));
    host.as_object_mut()
        .ok_or_else(|| DriverError::internal("Docker HostConfig must be an object"))?
        .insert(
            "RestartPolicy".to_owned(),
            json!({"Name":policy.name(),"MaximumRetryCount":0}),
        );
    Ok(())
}

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

/// Execute a fixed, driver-owned command and return bounded stdout.
///
/// `Tty=true` makes the Docker Engine return an unframed byte stream. This is
/// used only for small machine-readable observations; caller-controlled input
/// must never reach `command`.
pub(super) async fn docker_exec_capture(
    state: &DriverState,
    container: &str,
    command: &[&str],
    maximum_output: usize,
) -> Result<Vec<u8>, DriverError> {
    let response = state
        .runtime
        .client
        .post(
            state
                .runtime
                .endpoint(&format!("/containers/{container}/exec")),
        )
        .json(&json!({
            "AttachStdout":true,
            "AttachStderr":true,
            "Tty":true,
            "Cmd":command
        }))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker observation exec create returned {}",
            response.status()
        )));
    }
    let id = response
        .json::<Value>()
        .await
        .map_err(DriverError::internal)?
        .get("Id")
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::internal("Docker observation exec id missing"))?
        .to_owned();
    let response = state
        .runtime
        .client
        .post(state.runtime.endpoint(&format!("/exec/{id}/start")))
        .json(&json!({"Detach":false,"Tty":true}))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker observation exec start returned {}",
            response.status()
        )));
    }
    let mut output = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(DriverError::internal)?;
        if output.len().saturating_add(chunk.len()) > maximum_output {
            return Err(DriverError::internal(
                "Docker observation output exceeded its bound",
            ));
        }
        output.extend_from_slice(&chunk);
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
                Some(0) => Ok(output),
                Some(code) => Err(DriverError::internal(format!(
                    "container observation command exited with {code}"
                ))),
                None => Err(DriverError::internal(
                    "Docker observation exec exit code missing",
                )),
            };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(DriverError::internal("Docker observation exec timed out"))
}

pub(super) async fn docker_container_exists(
    state: &DriverState,
    name: &str,
) -> Result<bool, DriverError> {
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.container_exists(name).await;
    }
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.assert_image_present(reference).await;
    }
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.image_inspect(reference).await;
    }
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.inspect_container(name).await;
    }
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

pub(super) const WORKSPACE_RUNTIME_PAGE_LIMIT: usize = 500;
const WORKSPACE_RUNTIME_PAGE_MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct WorkspaceRuntimePage {
    pub(super) names: Vec<String>,
    pub(super) next_cursor: Option<String>,
}

fn parse_workspace_runtime_page(
    rows: Vec<Value>,
    limit: usize,
) -> Result<WorkspaceRuntimePage, DriverError> {
    if !(1..=WORKSPACE_RUNTIME_PAGE_LIMIT).contains(&limit) || rows.len() > limit {
        return Err(DriverError::internal(
            "workspace runtime page exceeded its bound",
        ));
    }
    let mut names = Vec::with_capacity(rows.len());
    let mut ids = BTreeSet::new();
    let mut next_cursor = None;
    for row in rows {
        let id = row
            .get("Id")
            .and_then(Value::as_str)
            .filter(|value| {
                (12..=64).contains(&value.len())
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| DriverError::internal("workspace runtime cursor is invalid"))?;
        if !ids.insert(id.to_owned()) {
            return Err(DriverError::internal(
                "workspace runtime page contains duplicate cursors",
            ));
        }
        let aliases = row
            .get("Names")
            .and_then(Value::as_array)
            .filter(|values| values.len() == 1)
            .ok_or_else(|| DriverError::internal("workspace runtime name is ambiguous"))?;
        let name = aliases[0]
            .as_str()
            .and_then(|value| value.strip_prefix('/'))
            .filter(|value| !value.is_empty())
            .filter(|value| !value.starts_with('/'))
            .ok_or_else(|| DriverError::internal("workspace runtime name is invalid"))?;
        validate_name(name)?;
        names.push(name.to_owned());
        next_cursor = Some(id.to_owned());
    }
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DriverError::internal(
            "workspace runtime page contains duplicate names",
        ));
    }
    Ok(WorkspaceRuntimePage { names, next_cursor })
}

pub(super) async fn docker_workspace_container_page(
    state: &DriverState,
    before: Option<&str>,
    limit: usize,
) -> Result<WorkspaceRuntimePage, DriverError> {
    if !(1..=WORKSPACE_RUNTIME_PAGE_LIMIT).contains(&limit)
        || before.is_some_and(|value| {
            !(12..=64).contains(&value.len())
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(DriverError::internal(
            "workspace runtime page request is invalid",
        ));
    }
    let filters = json!({
        "label": [format!("mb.workspace={}", state.config.workspace_namespace)]
    })
    .to_string();
    let query = {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query
            .append_pair("all", "true")
            .append_pair("filters", &filters)
            .append_pair("limit", &limit.to_string());
        if let Some(before) = before {
            query.append_pair("before", before);
        }
        query.finish()
    };
    let response = state
        .runtime
        .client
        .get(state.runtime.endpoint(&format!("/containers/json?{query}")))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker container list returned {}",
            response.status()
        )));
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(DriverError::internal)?;
        if body.len().saturating_add(chunk.len()) > WORKSPACE_RUNTIME_PAGE_MAX_BYTES {
            return Err(DriverError::internal(
                "workspace runtime page body exceeded its bound",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    let rows = serde_json::from_slice::<Vec<Value>>(&body).map_err(DriverError::internal)?;
    parse_workspace_runtime_page(rows, limit)
}

pub(super) async fn docker_workspace_containers(
    state: &DriverState,
) -> Result<Vec<String>, DriverError> {
    let mut names = Vec::new();
    let mut before = None;
    loop {
        let page =
            docker_workspace_container_page(state, before.as_deref(), WORKSPACE_RUNTIME_PAGE_LIMIT)
                .await?;
        let full = page.names.len() == WORKSPACE_RUNTIME_PAGE_LIMIT;
        if full && page.next_cursor.as_deref() == before.as_deref() {
            return Err(DriverError::internal(
                "workspace runtime cursor did not advance",
            ));
        }
        before = page.next_cursor;
        names.extend(page.names);
        if !full {
            break;
        }
    }
    names.sort();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DriverError::internal(
            "workspace runtime inventory contains duplicate names",
        ));
    }
    Ok(names)
}

pub(super) async fn docker_create_container(
    state: &DriverState,
    name: &str,
    restart_policy: DockerRestartPolicy,
    mut body: Value,
) -> Result<(), DriverError> {
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.create_archive_container(name, &body).await;
    }
    apply_restart_policy(&mut body, restart_policy)?;
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

pub(super) async fn docker_update_restart_policy(
    state: &DriverState,
    name: &str,
    restart_policy: DockerRestartPolicy,
) -> Result<(), DriverError> {
    let response = state
        .runtime
        .client
        .post(
            state
                .runtime
                .endpoint(&format!("/containers/{name}/update")),
        )
        .json(&json!({
            "RestartPolicy": {
                "Name": restart_policy.name(),
                "MaximumRetryCount": 0
            }
        }))
        .send()
        .await
        .map_err(DriverError::internal)?;
    if !response.status().is_success() {
        return Err(DriverError::internal(format!(
            "Docker restart-policy update returned {}",
            response.status()
        )));
    }
    Ok(())
}

pub(super) async fn docker_ensure_restart_policy(
    state: &DriverState,
    name: &str,
    restart_policy: DockerRestartPolicy,
) -> Result<bool, DriverError> {
    let inspect = docker_inspect_container(state, name).await?;
    if observed_restart_policy(&inspect) == Some(restart_policy.name()) {
        return Ok(false);
    }
    docker_update_restart_policy(state, name, restart_policy).await?;
    let observed = docker_inspect_container(state, name).await?;
    if observed_restart_policy(&observed) != Some(restart_policy.name()) {
        return Err(DriverError::internal(
            "Docker restart-policy postcondition did not converge",
        ));
    }
    Ok(true)
}

pub(super) fn observed_restart_policy(inspect: &Value) -> Option<&str> {
    inspect
        .pointer("/HostConfig/RestartPolicy/Name")
        .and_then(Value::as_str)
}

pub(super) async fn docker_start_container(
    state: &DriverState,
    name: &str,
) -> Result<(), DriverError> {
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.start_container(name).await;
    }
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.stop_container(name).await;
    }
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
            "Docker signal returned {}",
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.delete_container(name).await;
    }
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.ensure_volume(name).await;
    }
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.volume_exists(name).await;
    }
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend
            .create_extension_volume(name, manifest_digest, payload_digest)
            .await;
    }
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.delete_volume(name).await;
    }
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.get_archive(container, path, maximum).await;
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
    if let RuntimeBackend::Quadlet(backend) = &state.backend {
        return backend.put_archive(container, path, archive).await;
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
    fn docker_runtime_uses_the_supported_engine_api() {
        let runtime = ContainerRuntime {
            client: reqwest::Client::new(),
        };
        assert_eq!(runtime.endpoint("/info"), "http://localhost/v1.47/info");
    }

    #[test]
    fn runtime_kind_is_closed() {
        assert_eq!(
            DriverBackendKind::parse("docker").unwrap(),
            DriverBackendKind::Docker
        );
        assert_eq!(
            DriverBackendKind::parse("quadlet").unwrap(),
            DriverBackendKind::Quadlet
        );
        assert!(DriverBackendKind::parse("podman").is_err());
    }

    #[test]
    fn every_create_request_gets_an_explicit_closed_restart_policy() {
        let mut persistent = json!({"Image":"paperless","HostConfig":{"ReadonlyRootfs":true}});
        apply_restart_policy(&mut persistent, DockerRestartPolicy::UnlessStopped).unwrap();
        assert_eq!(
            persistent.pointer("/HostConfig/RestartPolicy/Name"),
            Some(&json!("unless-stopped"))
        );
        assert_eq!(
            persistent.pointer("/HostConfig/RestartPolicy/MaximumRetryCount"),
            Some(&json!(0))
        );

        let mut job = json!({"Image":"helper"});
        apply_restart_policy(&mut job, DockerRestartPolicy::No).unwrap();
        assert_eq!(
            job.pointer("/HostConfig/RestartPolicy/Name"),
            Some(&json!("no"))
        );
    }

    #[test]
    fn workspace_runtime_pages_are_bounded_and_cursor_by_server_order() {
        let page = parse_workspace_runtime_page(
            vec![
                json!({"Id":"bbbbbbbbbbbb", "Names":["/mb-z"]}),
                json!({"Id":"aaaaaaaaaaaa", "Names":["/mb-a"]}),
            ],
            2,
        )
        .unwrap();
        assert_eq!(page.names, vec!["mb-a", "mb-z"]);
        assert_eq!(page.next_cursor.as_deref(), Some("aaaaaaaaaaaa"));

        assert!(
            parse_workspace_runtime_page(vec![json!({"Id":"aaaaaaaaaaaa", "Names":["/mb-a"]})], 0,)
                .is_err()
        );
        assert!(
            parse_workspace_runtime_page(
                vec![
                    json!({"Id":"aaaaaaaaaaaa", "Names":["/mb-a"]}),
                    json!({"Id":"bbbbbbbbbbbb", "Names":["/mb-b"]}),
                ],
                1,
            )
            .is_err()
        );
    }

    #[test]
    fn workspace_runtime_pages_reject_ambiguous_or_duplicate_identity() {
        assert!(
            parse_workspace_runtime_page(
                vec![json!({"Id":"not-a-container-id", "Names":["/mb-a"]})],
                1,
            )
            .is_err()
        );
        assert!(
            parse_workspace_runtime_page(
                vec![json!({"Id":"aaaaaaaaaaaa", "Names":["/mb-a", "/mb-alias"]})],
                1,
            )
            .is_err()
        );
        assert!(
            parse_workspace_runtime_page(
                vec![json!({"Id":"aaaaaaaaaaaa", "Names":["//mb-a"]})],
                1,
            )
            .is_err()
        );
        assert!(
            parse_workspace_runtime_page(
                vec![
                    json!({"Id":"aaaaaaaaaaaa", "Names":["/mb-a"]}),
                    json!({"Id":"aaaaaaaaaaaa", "Names":["/mb-b"]}),
                ],
                2,
            )
            .is_err()
        );
        assert!(
            parse_workspace_runtime_page(
                vec![
                    json!({"Id":"aaaaaaaaaaaa", "Names":["/mb-a"]}),
                    json!({"Id":"bbbbbbbbbbbb", "Names":["/mb-a"]}),
                ],
                2,
            )
            .is_err()
        );
    }
}
