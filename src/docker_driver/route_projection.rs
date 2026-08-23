//! Typed, immutable workshop route projections.
//!
//! Parsing is deliberately stricter than rendering. A projection is accepted
//! only when its six-field JSON shape, canonical digest, database identity,
//! hostnames, Paperless mode, and sorted custom-hostname set all agree. This
//! keeps route producers from deriving physical configuration from mutable
//! route-file bytes.

use super::*;

const PROJECTION_FIELD_COUNT: usize = 6;
const MAX_CUSTOM_HOSTNAMES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RouteDisposition {
    Present,
    Absent,
}

impl RouteDisposition {
    #[allow(dead_code)] // consumed by the immutable release-overlay sealer
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, DriverError> {
        match value {
            "present" => Ok(Self::Present),
            "absent" => Ok(Self::Absent),
            _ => Err(DriverError::internal(
                "route projection disposition is invalid",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PaperlessRouteMode {
    Absent,
    ReadWrite,
    ReadOnly,
}

impl PaperlessRouteMode {
    pub(super) fn parse(value: &str) -> Result<Self, DriverError> {
        match value {
            "absent" => Ok(Self::Absent),
            "read_write" => Ok(Self::ReadWrite),
            "read_only" => Ok(Self::ReadOnly),
            _ => Err(DriverError::internal(
                "route projection Paperless mode is invalid",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RouteProjection {
    disposition: RouteDisposition,
    database_id: Option<Uuid>,
    database_ref: Option<String>,
    public_hostname: Option<String>,
    paperless_mode: PaperlessRouteMode,
    paperless_hostname: Option<String>,
    custom_hostnames: Vec<CustomHostnameRoute>,
    projection_digest: String,
}

pub(super) struct RouteRuntime<'a> {
    pub(super) odoo_upstream: &'a str,
    pub(super) paperless_upstream: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RenderedRoute {
    contents: Option<String>,
    rendered_digest: String,
}

impl RenderedRoute {
    pub(super) fn contents(&self) -> Option<&str> {
        self.contents.as_deref()
    }

    pub(super) fn into_contents(self) -> Option<String> {
        self.contents
    }

    pub(super) fn rendered_digest(&self) -> &str {
        &self.rendered_digest
    }

    /// Fold one route into a deterministic, streaming set digest. Every
    /// variable-width field is length framed, so callers never concatenate or
    /// retain the rendered fleet.
    #[allow(dead_code)] // consumed by the immutable release-overlay sealer
    pub(super) fn update_evidence_digest(
        &self,
        hasher: &mut Sha256,
        workshop_id: Uuid,
        generation: i64,
        projection_digest: &str,
        disposition: RouteDisposition,
    ) -> Result<(), DriverError> {
        if workshop_id.is_nil() || generation <= 0 || !valid_sha256(projection_digest) {
            return Err(DriverError::internal("route evidence identity is invalid"));
        }
        hasher.update(workshop_id.as_bytes());
        hasher.update(generation.to_be_bytes());
        update_framed(hasher, projection_digest.as_bytes())?;
        update_framed(hasher, disposition.as_str().as_bytes())?;
        update_framed(hasher, self.rendered_digest.as_bytes())
    }
}

impl RouteProjection {
    /// Parse an optional database projection without weakening absent-route
    /// evidence. Recovery exits historically omit the JSON body for an absent
    /// tombstone, so reconstruct its one canonical six-field value and still
    /// require the persisted digest to match it exactly.
    pub(super) fn parse_optional(
        projection: Option<&Value>,
        expected_digest: &str,
        disposition: RouteDisposition,
    ) -> Result<Self, DriverError> {
        match (projection, disposition) {
            (Some(projection), disposition) => {
                Self::parse(projection, expected_digest, disposition)
            }
            (None, RouteDisposition::Absent) => {
                let absent = canonical_absent_projection();
                Self::parse(&absent, expected_digest, RouteDisposition::Absent)
            }
            (None, RouteDisposition::Present) => Err(DriverError::internal(
                "present route projection payload is absent",
            )),
        }
    }

    pub(super) fn parse(
        projection: &Value,
        expected_digest: &str,
        disposition: RouteDisposition,
    ) -> Result<Self, DriverError> {
        if !valid_sha256(expected_digest)
            || projection.as_object().map(serde_json::Map::len) != Some(PROJECTION_FIELD_COUNT)
        {
            return Err(DriverError::internal("route projection shape is invalid"));
        }
        let canonical = serde_jcs::to_vec(projection)
            .map_err(|_| DriverError::internal("route projection is not canonical"))?;
        if format!("sha256:{:x}", Sha256::digest(canonical)) != expected_digest {
            return Err(DriverError::internal(
                "route projection digest does not match its payload",
            ));
        }
        let object = projection
            .as_object()
            .expect("the projection object shape was checked");
        for key in [
            "database_id",
            "database_ref",
            "public_hostname",
            "paperless_mode",
            "paperless_hostname",
            "custom_hostnames",
        ] {
            if !object.contains_key(key) {
                return Err(DriverError::internal("route projection shape is invalid"));
            }
        }

        match disposition {
            RouteDisposition::Absent => {
                let absent = canonical_absent_projection();
                if projection != &absent {
                    return Err(DriverError::internal(
                        "absent route projection shape is invalid",
                    ));
                }
                Ok(Self {
                    disposition,
                    database_id: None,
                    database_ref: None,
                    public_hostname: None,
                    paperless_mode: PaperlessRouteMode::Absent,
                    paperless_hostname: None,
                    custom_hostnames: Vec::new(),
                    projection_digest: expected_digest.to_owned(),
                })
            }
            RouteDisposition::Present => {
                let database_id_text = required_string(projection, "database_id")?;
                let database_id = Uuid::parse_str(database_id_text)
                    .ok()
                    .filter(|value| {
                        value.to_string() == database_id_text
                            && value.get_variant() == uuid::Variant::RFC4122
                            && (1..=5).contains(&value.get_version_num())
                    })
                    .ok_or_else(|| DriverError::internal("route database UUID is invalid"))?;
                let database_ref = required_string(projection, "database_ref")?;
                if database_ref != crate::domain::opaque_database_ref(database_id) {
                    return Err(DriverError::internal(
                        "route database reference does not match its UUID",
                    ));
                }
                let public_hostname = projection_hostname(projection, "public_hostname")?;
                let paperless_mode =
                    PaperlessRouteMode::parse(required_string(projection, "paperless_mode")?)?;
                let paperless_hostname = match paperless_mode {
                    PaperlessRouteMode::Absent
                        if projection
                            .get("paperless_hostname")
                            .is_some_and(Value::is_null) =>
                    {
                        None
                    }
                    PaperlessRouteMode::ReadOnly | PaperlessRouteMode::ReadWrite => {
                        Some(projection_hostname(projection, "paperless_hostname")?.to_owned())
                    }
                    PaperlessRouteMode::Absent => {
                        return Err(DriverError::internal(
                            "absent Paperless route has a hostname",
                        ));
                    }
                };
                let custom_hostnames = parse_custom_hostnames(projection)?;
                Ok(Self {
                    disposition,
                    database_id: Some(database_id),
                    database_ref: Some(database_ref.to_owned()),
                    public_hostname: Some(public_hostname.to_owned()),
                    paperless_mode,
                    paperless_hostname,
                    custom_hostnames,
                    projection_digest: expected_digest.to_owned(),
                })
            }
        }
    }

    pub(super) const fn disposition(&self) -> RouteDisposition {
        self.disposition
    }

    pub(super) const fn database_id(&self) -> Option<Uuid> {
        self.database_id
    }

    pub(super) fn database_ref(&self) -> Option<&str> {
        self.database_ref.as_deref()
    }

    pub(super) fn public_hostname(&self) -> Option<&str> {
        self.public_hostname.as_deref()
    }

    pub(super) const fn paperless_mode(&self) -> PaperlessRouteMode {
        self.paperless_mode
    }

    pub(super) fn paperless_hostname(&self) -> Option<&str> {
        self.paperless_hostname.as_deref()
    }

    #[allow(dead_code)] // consumed by the immutable release-overlay snapshot
    pub(super) fn projection_digest(&self) -> &str {
        &self.projection_digest
    }

    pub(super) fn render(
        &self,
        runtime: Option<RouteRuntime<'_>>,
    ) -> Result<RenderedRoute, DriverError> {
        let contents: Option<String> = match self.disposition {
            RouteDisposition::Absent => {
                if runtime.is_some() {
                    return Err(DriverError::internal(
                        "absent route projection received a runtime",
                    ));
                }
                None
            }
            RouteDisposition::Present => {
                let runtime = runtime.ok_or_else(|| {
                    DriverError::internal("present route projection runtime is absent")
                })?;
                runtime_backend::validate_name(runtime.odoo_upstream)?;
                if let Some(paperless) = runtime.paperless_upstream {
                    runtime_backend::validate_name(paperless)?;
                }
                match (self.paperless_mode, runtime.paperless_upstream) {
                    (PaperlessRouteMode::Absent, None)
                    | (PaperlessRouteMode::ReadOnly | PaperlessRouteMode::ReadWrite, Some(_)) => {}
                    _ => {
                        return Err(DriverError::internal(
                            "Paperless route runtime does not match its projection",
                        ));
                    }
                }
                Some(route_config_for_upstream(
                    self.database_ref
                        .as_deref()
                        .expect("present projections have a database reference"),
                    self.public_hostname
                        .as_deref()
                        .expect("present projections have a public hostname"),
                    runtime.odoo_upstream,
                    self.paperless_hostname
                        .as_deref()
                        .zip(runtime.paperless_upstream),
                    self.paperless_mode == PaperlessRouteMode::ReadOnly,
                    &self.custom_hostnames,
                ))
            }
        };
        let rendered_digest = format!(
            "sha256:{:x}",
            Sha256::digest(contents.as_deref().unwrap_or_default().as_bytes())
        );
        Ok(RenderedRoute {
            contents,
            rendered_digest,
        })
    }

    pub(super) fn render_maintenance(&self) -> Result<RenderedRoute, DriverError> {
        let contents: Option<String> = match self.disposition {
            RouteDisposition::Absent => None,
            RouteDisposition::Present => {
                let mut hostnames = vec![
                    self.public_hostname
                        .as_deref()
                        .expect("present projections have a public hostname"),
                ];
                hostnames.extend(self.paperless_hostname.as_deref());
                hostnames.extend(
                    self.custom_hostnames
                        .iter()
                        .map(|route| route.hostname.as_str()),
                );
                hostnames.sort_unstable();
                hostnames.dedup();
                Some(
                    hostnames
                        .iter()
                        .map(|name| format!("server {{\n  listen 8080;\n  server_name {name};\n  add_header Retry-After 120 always;\n  location / {{ return 503; }}\n}}\n"))
                        .collect(),
                )
            }
        };
        let rendered_digest = format!(
            "sha256:{:x}",
            Sha256::digest(contents.as_deref().unwrap_or_default().as_bytes())
        );
        Ok(RenderedRoute {
            contents,
            rendered_digest,
        })
    }
}

fn canonical_absent_projection() -> Value {
    json!({"database_id":null,"database_ref":null,
        "public_hostname":null,"paperless_mode":"absent",
        "paperless_hostname":null,"custom_hostnames":[]})
}

fn required_string<'a>(projection: &'a Value, key: &str) -> Result<&'a str, DriverError> {
    projection
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| DriverError::internal(format!("route projection {key} is invalid")))
}

fn projection_hostname<'a>(projection: &'a Value, key: &str) -> Result<&'a str, DriverError> {
    let value = required_string(projection, key)?;
    if hostname_is_valid(value) {
        Ok(value)
    } else {
        Err(DriverError::internal(format!(
            "route projection {key} is invalid"
        )))
    }
}

fn hostname_is_valid(value: &str) -> bool {
    (3..=253).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && !value.contains("..")
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
}

fn parse_custom_hostnames(projection: &Value) -> Result<Vec<CustomHostnameRoute>, DriverError> {
    let values = projection
        .get("custom_hostnames")
        .and_then(Value::as_array)
        .filter(|values| values.len() <= MAX_CUSTOM_HOSTNAMES)
        .ok_or_else(|| DriverError::internal("custom hostname projection is invalid"))?;
    let mut result = Vec::with_capacity(values.len());
    let mut previous: Option<&str> = None;
    let mut canonical_seen = false;
    for value in values {
        let object = value.as_object().filter(|object| {
            object.len() == 2 && object.contains_key("hostname") && object.contains_key("canonical")
        });
        let object =
            object.ok_or_else(|| DriverError::internal("custom hostname projection is invalid"))?;
        let hostname = projection_hostname(value, "hostname")?;
        if previous.is_some_and(|previous| previous >= hostname) {
            return Err(DriverError::internal(
                "custom hostname projection is not strictly ordered",
            ));
        }
        let canonical = object
            .get("canonical")
            .and_then(Value::as_bool)
            .ok_or_else(|| DriverError::internal("custom hostname canonical flag is invalid"))?;
        if canonical && canonical_seen {
            return Err(DriverError::internal(
                "custom hostname projection has multiple canonical names",
            ));
        }
        canonical_seen |= canonical;
        previous = Some(hostname);
        result.push(CustomHostnameRoute {
            hostname: hostname.to_owned(),
            canonical,
        });
    }
    Ok(result)
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[allow(dead_code)] // consumed through the future release-overlay evidence API
fn update_framed(hasher: &mut Sha256, value: &[u8]) -> Result<(), DriverError> {
    let length = u32::try_from(value.len())
        .map_err(|_| DriverError::internal("route evidence field exceeded its bound"))?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(projection: &Value) -> String {
        format!(
            "sha256:{:x}",
            Sha256::digest(serde_jcs::to_vec(projection).unwrap())
        )
    }

    fn present(mode: &str, paperless: Value, custom: Value) -> Value {
        let id = Uuid::parse_str("018f0b90-2f62-4c87-8a9d-20dc21a55701").unwrap();
        json!({
            "database_id": id,
            "database_ref": crate::domain::opaque_database_ref(id),
            "public_hostname": "tenant.example.test",
            "paperless_mode": mode,
            "paperless_hostname": paperless,
            "custom_hostnames": custom,
        })
    }

    #[test]
    fn renders_canonical_and_paperless_modes() {
        let plain = present("absent", Value::Null, json!([]));
        let parsed =
            RouteProjection::parse(&plain, &digest(&plain), RouteDisposition::Present).unwrap();
        let rendered = parsed
            .render(Some(RouteRuntime {
                odoo_upstream: "odoo-blue",
                paperless_upstream: None,
            }))
            .unwrap();
        assert!(rendered.contents().unwrap().contains("odoo-blue:8069"));
        assert!(!rendered.contents().unwrap().contains(":8000"));

        for (mode, read_only) in [("read_write", false), ("read_only", true)] {
            let value = present(mode, json!("docs.example.test"), json!([]));
            let parsed =
                RouteProjection::parse(&value, &digest(&value), RouteDisposition::Present).unwrap();
            let rendered = parsed
                .render(Some(RouteRuntime {
                    odoo_upstream: "odoo-green",
                    paperless_upstream: Some("paperless-tenant"),
                }))
                .unwrap();
            assert!(
                rendered
                    .contents()
                    .unwrap()
                    .contains("paperless-tenant:8000")
            );
            assert_eq!(
                rendered
                    .contents()
                    .unwrap()
                    .contains("limit_except GET HEAD OPTIONS"),
                read_only
            );
        }
    }

    #[test]
    fn custom_canonical_and_maintenance_render_deterministically() {
        let value = present(
            "read_only",
            json!("docs.example.test"),
            json!([
                {"hostname":"a.example.test","canonical":false},
                {"hostname":"shop.example.test","canonical":true}
            ]),
        );
        let parsed =
            RouteProjection::parse(&value, &digest(&value), RouteDisposition::Present).unwrap();
        let route = parsed
            .render(Some(RouteRuntime {
                odoo_upstream: "odoo-green",
                paperless_upstream: Some("paperless-tenant"),
            }))
            .unwrap();
        assert!(
            route
                .contents()
                .unwrap()
                .contains("server_name shop.example.test tenant.example.test;")
        );
        assert!(
            route
                .contents()
                .unwrap()
                .contains("return 308 https://shop.example.test$request_uri;")
        );

        let maintenance = parsed.render_maintenance().unwrap();
        let contents = maintenance.contents().unwrap();
        let names = [
            "a.example.test",
            "docs.example.test",
            "shop.example.test",
            "tenant.example.test",
        ];
        let positions = names.map(|name| contents.find(name).unwrap());
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(contents.matches("return 503").count(), names.len());
        assert!(!contents.contains("proxy_pass"));
    }

    #[test]
    fn absent_route_has_canonical_empty_render_and_streaming_evidence() {
        let value = canonical_absent_projection();
        let parsed =
            RouteProjection::parse(&value, &digest(&value), RouteDisposition::Absent).unwrap();
        let rendered = parsed.render(None).unwrap();
        assert_eq!(rendered.contents(), None);
        assert_eq!(
            rendered.rendered_digest(),
            format!("sha256:{:x}", Sha256::digest([]))
        );
        let workshop = Uuid::new_v4();
        let mut first = Sha256::new();
        rendered
            .update_evidence_digest(
                &mut first,
                workshop,
                1,
                parsed.projection_digest(),
                parsed.disposition(),
            )
            .unwrap();
        let mut second = Sha256::new();
        rendered
            .update_evidence_digest(
                &mut second,
                workshop,
                1,
                parsed.projection_digest(),
                parsed.disposition(),
            )
            .unwrap();
        assert_eq!(first.finalize(), second.finalize());
    }

    #[test]
    fn optional_absent_projection_reconstructs_only_the_canonical_digest() {
        let absent = canonical_absent_projection();
        let expected_digest = digest(&absent);
        let parsed =
            RouteProjection::parse_optional(None, &expected_digest, RouteDisposition::Absent)
                .unwrap();
        assert_eq!(parsed.disposition(), RouteDisposition::Absent);
        assert!(parsed.render(None).unwrap().contents().is_none());
        assert!(
            RouteProjection::parse_optional(
                None,
                &format!("sha256:{}", "0".repeat(64)),
                RouteDisposition::Absent,
            )
            .is_err()
        );
        assert!(
            RouteProjection::parse_optional(None, &expected_digest, RouteDisposition::Present)
                .is_err()
        );
    }

    #[test]
    fn rejects_digest_shape_identity_hostname_and_custom_drift() {
        let base = present("absent", Value::Null, json!([]));
        assert!(
            RouteProjection::parse(
                &base,
                &format!("sha256:{}", "0".repeat(64)),
                RouteDisposition::Present
            )
            .is_err()
        );

        let mut extra = base.clone();
        extra["extra"] = json!(true);
        assert!(
            RouteProjection::parse(&extra, &digest(&extra), RouteDisposition::Present).is_err()
        );

        let mut wrong_ref = base.clone();
        wrong_ref["database_ref"] = json!("mb_00000000000000000000000000000000");
        assert!(
            RouteProjection::parse(&wrong_ref, &digest(&wrong_ref), RouteDisposition::Present)
                .is_err()
        );

        let mut version_seven = base.clone();
        version_seven["database_id"] = json!("018f0b90-2f62-7c87-8a9d-20dc21a55701");
        assert!(
            RouteProjection::parse(
                &version_seven,
                &digest(&version_seven),
                RouteDisposition::Present
            )
            .is_err()
        );

        let mut hostname = base.clone();
        hostname["public_hostname"] = json!("Tenant..example.test");
        assert!(
            RouteProjection::parse(&hostname, &digest(&hostname), RouteDisposition::Present)
                .is_err()
        );

        for custom in [
            json!([{"hostname":"z.example.test","canonical":false},{"hostname":"a.example.test","canonical":false}]),
            json!([{"hostname":"a.example.test","canonical":true},{"hostname":"b.example.test","canonical":true}]),
            json!([{"hostname":"a.example.test","canonical":false,"extra":true}]),
        ] {
            let value = present("absent", Value::Null, custom);
            assert!(
                RouteProjection::parse(&value, &digest(&value), RouteDisposition::Present).is_err()
            );
        }
    }

    #[test]
    fn rejects_paperless_and_runtime_shape_mismatches() {
        let value = present("read_only", Value::Null, json!([]));
        assert!(
            RouteProjection::parse(&value, &digest(&value), RouteDisposition::Present).is_err()
        );
        let value = present("absent", json!("docs.example.test"), json!([]));
        assert!(
            RouteProjection::parse(&value, &digest(&value), RouteDisposition::Present).is_err()
        );

        let value = present("read_write", json!("docs.example.test"), json!([]));
        let parsed =
            RouteProjection::parse(&value, &digest(&value), RouteDisposition::Present).unwrap();
        assert!(
            parsed
                .render(Some(RouteRuntime {
                    odoo_upstream: "odoo",
                    paperless_upstream: None
                }))
                .is_err()
        );
        assert!(
            parsed
                .render(Some(RouteRuntime {
                    odoo_upstream: "../odoo",
                    paperless_upstream: Some("paperless")
                }))
                .is_err()
        );
    }

    #[test]
    fn streaming_evidence_rejects_nil_workshops() {
        let value = present("absent", Value::Null, json!([]));
        let parsed =
            RouteProjection::parse(&value, &digest(&value), RouteDisposition::Present).unwrap();
        let rendered = parsed
            .render(Some(RouteRuntime {
                odoo_upstream: "odoo",
                paperless_upstream: None,
            }))
            .unwrap();
        assert!(
            rendered
                .update_evidence_digest(
                    &mut Sha256::new(),
                    Uuid::nil(),
                    1,
                    parsed.projection_digest(),
                    parsed.disposition(),
                )
                .is_err()
        );
    }
}
