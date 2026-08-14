use super::*;

pub(super) async fn write_routes(
    state: &DriverState,
    workshop: Uuid,
    database_ref: &str,
    odoo_hostname: &str,
    paperless: Option<(&str, &str)>,
    paperless_read_only: bool,
) -> Result<(), DriverError> {
    let config = route_config(database_ref, odoo_hostname, paperless, paperless_read_only);
    let path = state.config.route_root.join(format!("{workshop}.conf"));
    let temporary = state.config.route_root.join(format!("{workshop}.conf.tmp"));
    let previous = std::fs::read(&path).ok();
    std::fs::write(&temporary, config).map_err(DriverError::internal)?;
    std::fs::rename(temporary, &path).map_err(DriverError::internal)?;
    if let Err(error) = docker_exec(state, &state.config.gateway_container, &["nginx", "-t"]).await
    {
        if let Some(previous) = previous {
            let _ = std::fs::write(&path, previous);
        } else {
            let _ = std::fs::remove_file(&path);
        }
        return Err(error);
    }
    docker_signal_container(state, &state.config.gateway_container, "HUP").await?;
    Ok(())
}

pub(super) fn route_config(
    database_ref: &str,
    odoo_hostname: &str,
    paperless: Option<(&str, &str)>,
    paperless_read_only: bool,
) -> String {
    let mut config = format!(
        "server {{\n  listen 8080;\n  server_name {odoo_hostname};\n  location / {{\n    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n    proxy_set_header X-Forwarded-Host $host;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $forwarded_proto;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $connection_upgrade;\n    proxy_set_header X-Odoo-Dbfilter '^{}\\Z';\n    set $tenant_upstream \"odoo:8069\";\n    proxy_pass http://$tenant_upstream;\n  }}\n}}\n",
        database_ref
    );
    if let Some((paperless_hostname, paperless_container)) = paperless {
        let mutation_gate = if paperless_read_only {
            "    limit_except GET HEAD OPTIONS { deny all; }\n"
        } else {
            ""
        };
        config.push_str(&format!(
            "server {{\n  listen 8080;\n  server_name {paperless_hostname};\n  location / {{\n{mutation_gate}    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n    proxy_set_header X-Forwarded-Host $host;\n    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n    proxy_set_header X-Forwarded-Proto $forwarded_proto;\n    proxy_set_header Upgrade $http_upgrade;\n    proxy_set_header Connection $connection_upgrade;\n    set $tenant_upstream \"{paperless_container}:8000\";\n    proxy_pass http://$tenant_upstream;\n  }}\n}}\n"
        ));
    }
    config
}

pub(super) async fn restrict_capability(
    state: &DriverState,
    workshop: Uuid,
    payload: &Value,
) -> Result<Value, DriverError> {
    if payload.get("capability").and_then(Value::as_str) != Some("documents") {
        return Err(DriverError::bad("unsupported gateway restriction"));
    }
    let database_ref = payload
        .get("database_ref")
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() == 35
                && value.starts_with("mb_")
                && value[3..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or_else(|| DriverError::bad("invalid database_ref"))?;
    let odoo_hostname = hostname(payload, "public_hostname")?;
    let paperless_hostname = hostname(payload, "paperless_hostname")?;
    let paperless_container = format!("mb-paperless-{}", tenant_key(workshop));
    let config = route_config(
        database_ref,
        odoo_hostname,
        Some((paperless_hostname, &paperless_container)),
        true,
    );
    let digest = format!("sha256:{:x}", Sha256::digest(config.as_bytes()));
    replace_route_config(state, workshop, config.as_bytes()).await?;
    Ok(json!({
        "adapter":"paperless_gateway_read_only","policy_digest":digest,
        "write_blocked":true,"historical_read_retained":true
    }))
}
