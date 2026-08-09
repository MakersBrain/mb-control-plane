use serde_json::{Map, Value, json};

/// The public contract is emitted from the executable so deployments and
/// generated clients can inspect the exact route release they are running.
pub fn document() -> Value {
    let routes = [
        ("/v1/version", "get", false),
        ("/v1/me", "get", true),
        ("/v1/platform/overview", "get", true),
        ("/v1/platform/workshops", "get", true),
        ("/v1/platform/workshops/{id}", "get", true),
        ("/v1/platform/workshops/{id}/deletion", "post", true),
        ("/v1/platform/workshops/{id}/reconcile", "post", true),
        ("/v1/platform/operations", "get", true),
        ("/v1/platform/users", "get", true),
        ("/v1/platform/status", "get", true),
        ("/v1/platform/email-deliveries", "get", true),
        ("/v1/platform/audit-events", "get", true),
        ("/v1/identity/link", "post", true),
        ("/v1/workshops", "get", true),
        ("/v1/workshops", "post", true),
        ("/v1/workshops/{id}", "get", true),
        ("/v1/workshops/{id}/members", "get", true),
        ("/v1/workshops/{id}/invitations", "get", true),
        ("/v1/workshops/{id}/invitations", "post", true),
        ("/v1/invitations/{id}/resend", "post", true),
        ("/v1/invitations/{id}", "delete", true),
        ("/v1/invitations/{token}/validate", "get", false),
        ("/v1/invitations/{token}/accept", "post", true),
        ("/v1/workshops/{id}/members/{user_id}", "patch", true),
        ("/v1/workshops/{id}/members/{user_id}", "delete", true),
        ("/v1/workshops/{id}/ownership-transfers", "get", true),
        ("/v1/workshops/{id}/ownership-transfers", "post", true),
        ("/v1/ownership-transfers/{id}/accept", "post", true),
        ("/v1/workshops/{id}/integrations", "get", true),
        ("/v1/workshops/{id}/modules", "get", true),
        (
            "/v1/workshops/{id}/modules/{module_key}/enable",
            "post",
            true,
        ),
        ("/v1/workshops/{id}/database", "get", true),
        ("/v1/workshops/{id}/database/snapshots", "post", true),
        ("/v1/workshops/{id}/database/backups", "post", true),
        ("/v1/workshops/{id}/database/restores", "post", true),
        ("/v1/workshops/{id}/database/duplicates", "post", true),
        ("/v1/operations/{id}", "get", true),
        (
            "/v1/workshops/{id}/database/backups/{recovery_id}/download",
            "post",
            true,
        ),
        ("/v1/operations/{id}/retry", "post", true),
    ];
    let mut paths = Map::new();
    for (path, method, secured) in routes {
        let item = paths
            .entry(path)
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .expect("path item");
        item.insert(method.into(),json!({"responses":{"200":{"description":"Successful response"},"202":{"description":"Durable operation accepted"},"400":{"description":"Validation failed"},"401":{"description":"Authentication required"},"403":{"description":"Authority refused"}},"security":if secured{json!([{"rauthy":[]}])}else{json!([])}}));
    }
    json!({"openapi":"3.1.0","info":{"title":"MakersBrain control API","version":env!("CARGO_PKG_VERSION")},"servers":[{"url":"/"}],"paths":paths,"components":{"securitySchemes":{"rauthy":{"type":"http","scheme":"bearer","bearerFormat":"JWT","description":"Rauthy access token; workshop authority is resolved from PostgreSQL."}}}})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contract_contains_every_required_members_route() {
        let value = document();
        for path in [
            "/v1/me",
            "/v1/workshops/{id}/members",
            "/v1/workshops/{id}/invitations",
            "/v1/invitations/{token}/accept",
            "/v1/operations/{id}/retry",
            "/v1/workshops/{id}/database",
            "/v1/workshops/{id}/database/restores",
        ] {
            assert!(value["paths"].get(path).is_some(), "missing {path}")
        }
    }

    #[test]
    fn contract_contains_operator_observability_and_repair_routes() {
        let value = document();
        for path in [
            "/v1/platform/overview",
            "/v1/platform/workshops",
            "/v1/platform/workshops/{id}",
            "/v1/platform/workshops/{id}/reconcile",
            "/v1/platform/workshops/{id}/deletion",
            "/v1/platform/operations",
            "/v1/platform/users",
            "/v1/platform/status",
            "/v1/platform/email-deliveries",
            "/v1/platform/audit-events",
        ] {
            assert!(value["paths"].get(path).is_some(), "missing {path}")
        }
    }
}
