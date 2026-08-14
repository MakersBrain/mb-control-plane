use super::*;

pub(super) async fn docker_exec(
    state: &DriverState,
    container: &str,
    command: &[&str],
) -> Result<(), DriverError> {
    let response = state
        .docker
        .post(format!(
            "http://localhost/v1.47/containers/{container}/exec"
        ))
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
        .docker
        .post(format!("http://localhost/v1.47/exec/{id}/start"))
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
            .docker
            .get(format!("http://localhost/v1.47/exec/{id}/json"))
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
        .docker
        .get(format!("http://localhost/v1.47/containers/{name}/json"))
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

pub(super) async fn docker_inspect_container(
    state: &DriverState,
    name: &str,
) -> Result<Value, DriverError> {
    let response = state
        .docker
        .get(format!("http://localhost/v1.47/containers/{name}/json"))
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
    body: Value,
) -> Result<(), DriverError> {
    let response = state
        .docker
        .post(format!(
            "http://localhost/v1.47/containers/create?name={name}"
        ))
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
        .docker
        .post(format!("http://localhost/v1.47/containers/{name}/start"))
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
        .docker
        .post(format!(
            "http://localhost/v1.47/containers/{name}/stop?t=30"
        ))
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

pub(super) async fn docker_wait_container(
    state: &DriverState,
    name: &str,
) -> Result<i64, DriverError> {
    let response = state
        .docker
        .post(format!(
            "http://localhost/v1.47/containers/{name}/wait?condition=not-running"
        ))
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
        .docker
        .delete(format!(
            "http://localhost/v1.47/containers/{name}?force=true"
        ))
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
        .docker
        .post("http://localhost/v1.47/volumes/create")
        .json(&json!({"Name":name,"Labels":{"makersbrain.kind":"paperless-volume"}}))
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
