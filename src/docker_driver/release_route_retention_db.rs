//! Dormant typed database capability for immutable release-overlay retention.
#![allow(dead_code)]

use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::DriverError;
use super::gateway::{ReleaseOverlayGenerationIdentity, ReleaseOverlayKind};
use super::release_generation_fs::{
    ReleaseGenerationIntent, ReleaseGenerationName, validate_release_retention_generation_authority,
};
use super::route_generation_fs::validate_selector_target;

const MIN_TTL_SECONDS: i32 = 30;
const MAX_TTL_SECONDS: i32 = 3_600;
const MAX_DISCOVERY: i32 = 100;
const MAX_RELEASE_ROUTES: i32 = 500;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReleaseGenerationRetentionCursor {
    pub driver_operation_id: Uuid,
    pub overlay_kind: ReleaseOverlayKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ReleaseGenerationRetentionCandidate {
    pub driver_operation_id: Uuid,
    pub overlay_kind: ReleaseOverlayKind,
    pub selector: String,
    pub retention_not_before: OffsetDateTime,
}

#[derive(Clone)]
pub(super) struct ReleaseGenerationRetentionClaimRequest {
    pub driver_operation_id: Uuid,
    pub overlay_kind: ReleaseOverlayKind,
    pub instance_owner: Uuid,
    pub claim_token: Uuid,
    pub ttl_seconds: i32,
}

#[derive(Clone)]
pub(super) struct ReleaseGenerationRetentionClaim {
    pub driver_operation_id: Uuid,
    pub overlay_kind: ReleaseOverlayKind,
    pub instance_owner: Uuid,
    pub claim_token: Uuid,
    pub ttl_seconds: i32,
    pub claim_fence: i64,
    pub fleet_run_id: Uuid,
    pub selector: String,
    pub directory_device: u64,
    pub directory_inode: u64,
    pub expected_intent: Value,
    pub expected_identity: Value,
    pub intent: ReleaseGenerationIntent,
    pub identity: ReleaseOverlayGenerationIdentity,
    pub route_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClaimReleaseGenerationRetentionOutcome {
    Acquired,
    Replay,
    Busy,
    Ineligible,
    NotFound,
    Invalid,
}

pub(super) struct ClaimReleaseGenerationRetention {
    pub outcome: ClaimReleaseGenerationRetentionOutcome,
    pub claim: Option<ReleaseGenerationRetentionClaim>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ReleaseGenerationRetentionResolution {
    Deleted,
    AlreadyAbsent,
    ProtectedCurrent,
    IdentityMismatch,
}

impl ReleaseGenerationRetentionResolution {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Deleted => "deleted",
            Self::AlreadyAbsent => "already_absent",
            Self::ProtectedCurrent => "protected_current",
            Self::IdentityMismatch => "identity_mismatch",
        }
    }
}

#[derive(Serialize)]
pub(super) struct ReleaseGenerationRetentionEvidence<'a> {
    pub protocol_version: u8,
    pub driver_operation_id: Uuid,
    pub overlay_kind: &'a str,
    pub claim_fence: i64,
    pub resolution: &'a str,
    pub selector: &'a str,
    pub expected_intent: &'a Value,
    pub expected_identity: &'a Value,
    pub observed_current_selector: &'a str,
    pub observed_current_identity: &'a Value,
    pub target_present: bool,
    pub observed_target_device: Option<u64>,
    pub observed_target_inode: Option<u64>,
    pub mismatch_kind: Option<&'a str>,
    pub observed_target_identity: &'a Value,
}

type ClaimRow = (
    String,
    Option<i64>,
    Option<Uuid>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<Value>,
    Option<Value>,
    Option<i32>,
);

pub(super) async fn discover_release_retention_candidates(
    ledger: &PgPool,
    after: Option<ReleaseGenerationRetentionCursor>,
    limit: i32,
) -> Result<Vec<ReleaseGenerationRetentionCandidate>, DriverError> {
    if after
        .as_ref()
        .is_some_and(|cursor| cursor.driver_operation_id.is_nil())
        || !(1..=MAX_DISCOVERY).contains(&limit)
    {
        return Err(invalid("release retention discovery limit is invalid"));
    }
    let after_driver = after.as_ref().map(|cursor| cursor.driver_operation_id);
    let after_kind = after.as_ref().map(|cursor| cursor.overlay_kind.as_str());
    let rows: Vec<(Uuid, String, String, OffsetDateTime)> = sqlx::query_as(
        "select driver_operation_id,overlay_kind,selector,retention_not_before
           from control.discover_fleet_release_generation_retention_candidates($1,$2,$3)",
    )
    .bind(after_driver)
    .bind(after_kind)
    .bind(limit)
    .fetch_all(ledger)
    .await
    .map_err(DriverError::internal)?;
    let mut previous = after;
    rows.into_iter()
        .map(
            |(driver_operation_id, kind, selector, retention_not_before)| {
                let overlay_kind = parse_kind(&kind)?;
                let current = ReleaseGenerationRetentionCursor {
                    driver_operation_id,
                    overlay_kind,
                };
                if driver_operation_id.is_nil()
                    || previous.as_ref().is_some_and(|prior| {
                        (
                            prior.driver_operation_id,
                            overlay_kind_rank(prior.overlay_kind),
                        ) >= (driver_operation_id, overlay_kind_rank(overlay_kind))
                    })
                    || validate_selector_target(&selector).is_err()
                {
                    return Err(invalid("release retention discovery row is malformed"));
                }
                previous = Some(current);
                Ok(ReleaseGenerationRetentionCandidate {
                    driver_operation_id,
                    overlay_kind,
                    selector,
                    retention_not_before,
                })
            },
        )
        .collect()
}

const fn overlay_kind_rank(kind: ReleaseOverlayKind) -> u8 {
    match kind {
        ReleaseOverlayKind::Candidate => 0,
        ReleaseOverlayKind::Maintenance => 1,
    }
}

#[tracing::instrument(
    name = "deployment_driver.release_route_retention.claim_dormant",
    skip_all,
    fields(operation.id=%request.driver_operation_id, retention.kind=request.overlay_kind.as_str(),
        retention.outcome=tracing::field::Empty)
)]
pub(super) async fn claim_release_retention(
    ledger: &PgPool,
    request: &ReleaseGenerationRetentionClaimRequest,
) -> Result<ClaimReleaseGenerationRetention, DriverError> {
    validate_request(request)?;
    let row: ClaimRow = sqlx::query_as(
        "select outcome,claim_fence,fleet_run_id,selector,directory_device,directory_inode,
                expected_intent,expected_identity,route_count
           from control.claim_fleet_release_generation_retention($1,$2,$3,$4,$5)",
    )
    .bind(request.driver_operation_id)
    .bind(request.overlay_kind.as_str())
    .bind(request.instance_owner)
    .bind(request.claim_token)
    .bind(request.ttl_seconds)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("retention.outcome", row.0.as_str());
    parse_claim(request, row)
}

pub(super) async fn renew_release_retention_claim(
    ledger: &PgPool,
    claim: &ReleaseGenerationRetentionClaim,
) -> Result<bool, DriverError> {
    sqlx::query_scalar(
        "select control.renew_fleet_release_generation_retention_claim($1,$2,$3,$4,$5,$6)",
    )
    .bind(claim.driver_operation_id)
    .bind(claim.overlay_kind.as_str())
    .bind(claim.instance_owner)
    .bind(claim.claim_token)
    .bind(claim.claim_fence)
    .bind(claim.ttl_seconds)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)
}

#[tracing::instrument(
    name = "deployment_driver.release_route_retention.finish_dormant",
    skip_all,
    fields(operation.id=%claim.driver_operation_id, retention.kind=claim.overlay_kind.as_str(),
        retention.resolution=resolution.as_str(), retention.outcome=tracing::field::Empty)
)]
pub(super) async fn finish_release_retention(
    ledger: &PgPool,
    claim: &ReleaseGenerationRetentionClaim,
    resolution: ReleaseGenerationRetentionResolution,
    evidence: &ReleaseGenerationRetentionEvidence<'_>,
) -> Result<String, DriverError> {
    let evidence = serde_json::to_value(evidence).map_err(DriverError::internal)?;
    let outcome: String = sqlx::query_scalar(
        "select control.finish_fleet_release_generation_retention($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(claim.driver_operation_id)
    .bind(claim.overlay_kind.as_str())
    .bind(claim.instance_owner)
    .bind(claim.claim_token)
    .bind(claim.claim_fence)
    .bind(resolution.as_str())
    .bind(evidence)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("retention.outcome", outcome.as_str());
    if matches!(
        outcome.as_str(),
        "deleted"
            | "already_absent"
            | "protected_current"
            | "identity_mismatch"
            | "replay"
            | "conflict"
            | "claim_lost"
            | "not_found"
            | "invalid"
            | "evidence_mismatch"
    ) {
        Ok(outcome)
    } else {
        Err(invalid("release retention finish outcome is not closed"))
    }
}

fn parse_claim(
    request: &ReleaseGenerationRetentionClaimRequest,
    row: ClaimRow,
) -> Result<ClaimReleaseGenerationRetention, DriverError> {
    let outcome = match row.0.as_str() {
        "acquired" => ClaimReleaseGenerationRetentionOutcome::Acquired,
        "replay" => ClaimReleaseGenerationRetentionOutcome::Replay,
        "busy" => ClaimReleaseGenerationRetentionOutcome::Busy,
        "ineligible" => ClaimReleaseGenerationRetentionOutcome::Ineligible,
        "not_found" => ClaimReleaseGenerationRetentionOutcome::NotFound,
        "invalid" => ClaimReleaseGenerationRetentionOutcome::Invalid,
        _ => return Err(invalid("release retention claim outcome is invalid")),
    };
    if matches!(
        outcome,
        ClaimReleaseGenerationRetentionOutcome::Acquired
            | ClaimReleaseGenerationRetentionOutcome::Replay
    ) {
        return Ok(ClaimReleaseGenerationRetention {
            outcome,
            claim: Some(parse_acquired_claim(request, row)?),
        });
    }
    let empty = row.1.is_none()
        && row.2.is_none()
        && row.3.is_none()
        && row.4.is_none()
        && row.5.is_none()
        && row.6.is_none()
        && row.7.is_none()
        && row.8.is_none();
    match outcome {
        ClaimReleaseGenerationRetentionOutcome::Invalid
        | ClaimReleaseGenerationRetentionOutcome::NotFound
            if !empty =>
        {
            return Err(invalid("release retention refusal row shape is invalid"));
        }
        ClaimReleaseGenerationRetentionOutcome::Busy => {
            validate_refusal_summary(request, &row, false)?;
        }
        ClaimReleaseGenerationRetentionOutcome::Ineligible => {
            validate_refusal_summary(request, &row, true)?;
        }
        ClaimReleaseGenerationRetentionOutcome::Acquired
        | ClaimReleaseGenerationRetentionOutcome::Replay => unreachable!(),
        ClaimReleaseGenerationRetentionOutcome::Invalid
        | ClaimReleaseGenerationRetentionOutcome::NotFound => {}
    }
    Ok(ClaimReleaseGenerationRetention {
        outcome,
        claim: None,
    })
}

fn validate_refusal_summary(
    request: &ReleaseGenerationRetentionClaimRequest,
    row: &ClaimRow,
    include_evidence: bool,
) -> Result<(), DriverError> {
    if row.1.is_some()
        || row.2.is_none_or(|value| value.is_nil())
        || row
            .3
            .as_deref()
            .is_none_or(|selector| validate_selector_target(selector).is_err())
        || positive_u64(row.4, "refusal directory device").is_err()
        || positive_u64(row.5, "refusal directory inode").is_err()
        || row
            .8
            .is_none_or(|count| !(1..=MAX_RELEASE_ROUTES).contains(&count))
        || include_evidence != (row.6.is_some() && row.7.is_some())
        || (!include_evidence && (row.6.is_some() || row.7.is_some()))
    {
        return Err(invalid("release retention refusal summary is malformed"));
    }
    if include_evidence {
        let mut authenticated = row.clone();
        authenticated.0 = "acquired".into();
        authenticated.1 = Some(1);
        parse_acquired_claim(request, authenticated)?;
    } else {
        let fleet = row.2.expect("validated fleet run");
        let expected = ReleaseGenerationName::new(fleet, request.overlay_kind).selector_target();
        if row.3.as_deref() != Some(expected.as_str()) {
            return Err(invalid("release retention refusal selector differs"));
        }
    }
    Ok(())
}

fn parse_acquired_claim(
    request: &ReleaseGenerationRetentionClaimRequest,
    row: ClaimRow,
) -> Result<ReleaseGenerationRetentionClaim, DriverError> {
    let claim_fence = row
        .1
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid("release retention claim fence is invalid"))?;
    let fleet_run_id = row
        .2
        .filter(|value| !value.is_nil())
        .ok_or_else(|| invalid("release retention fleet run is invalid"))?;
    let selector = row
        .3
        .ok_or_else(|| invalid("release retention selector is absent"))?;
    let directory_device = positive_u64(row.4, "directory device")?;
    let directory_inode = positive_u64(row.5, "directory inode")?;
    let expected_intent = row
        .6
        .ok_or_else(|| invalid("release retention intent is absent"))?;
    let intent: ReleaseGenerationIntent = serde_json::from_value(expected_intent.clone())
        .map_err(|_| invalid("release retention intent is malformed"))?;
    let expected_identity = row
        .7
        .ok_or_else(|| invalid("release retention identity is absent"))?;
    let identity: ReleaseOverlayGenerationIdentity =
        serde_json::from_value(expected_identity.clone())
            .map_err(|_| invalid("release retention identity is malformed"))?;
    let route_count = row
        .8
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (1..=MAX_RELEASE_ROUTES as usize).contains(value))
        .ok_or_else(|| invalid("release retention route count is invalid"))?;
    validate_release_retention_generation_authority(&intent, &identity)
        .map_err(DriverError::internal)?;
    if intent.fleet_run_id != fleet_run_id
        || intent.driver_operation_id != request.driver_operation_id
        || intent.overlay_kind != request.overlay_kind
        || identity.fleet_run_id != fleet_run_id
        || identity.driver_operation_id != request.driver_operation_id
        || identity.overlay_kind != request.overlay_kind
        || selector
            != ReleaseGenerationName::new(fleet_run_id, request.overlay_kind).selector_target()
    {
        return Err(invalid("release retention claim authority differs"));
    }
    Ok(ReleaseGenerationRetentionClaim {
        driver_operation_id: request.driver_operation_id,
        overlay_kind: request.overlay_kind,
        instance_owner: request.instance_owner,
        claim_token: request.claim_token,
        ttl_seconds: request.ttl_seconds,
        claim_fence,
        fleet_run_id,
        selector,
        directory_device,
        directory_inode,
        expected_intent,
        expected_identity,
        intent,
        identity,
        route_count,
    })
}

fn validate_request(request: &ReleaseGenerationRetentionClaimRequest) -> Result<(), DriverError> {
    if request.driver_operation_id.is_nil()
        || request.instance_owner.is_nil()
        || request.claim_token.is_nil()
        || !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&request.ttl_seconds)
    {
        return Err(invalid("release retention claim request is invalid"));
    }
    Ok(())
}

fn parse_kind(value: &str) -> Result<ReleaseOverlayKind, DriverError> {
    serde_json::from_value(Value::String(value.to_owned()))
        .map_err(|_| invalid("release retention overlay kind is invalid"))
}

fn positive_u64(value: Option<i64>, description: &str) -> Result<u64, DriverError> {
    value
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid(format!("release retention {description} is invalid")))
}

fn invalid(message: impl Into<String>) -> DriverError {
    DriverError::internal(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ReleaseGenerationRetentionClaimRequest {
        ReleaseGenerationRetentionClaimRequest {
            driver_operation_id: Uuid::new_v4(),
            overlay_kind: ReleaseOverlayKind::Candidate,
            instance_owner: Uuid::new_v4(),
            claim_token: Uuid::new_v4(),
            ttl_seconds: 90,
        }
    }

    fn acquired_row(request: &ReleaseGenerationRetentionClaimRequest) -> ClaimRow {
        let fleet = Uuid::new_v4();
        let intent = ReleaseGenerationIntent::new(
            fleet,
            request.driver_operation_id,
            17,
            request.overlay_kind,
            "green",
        )
        .unwrap();
        let identity = ReleaseOverlayGenerationIdentity::new(
            fleet,
            request.driver_operation_id,
            17,
            request.overlay_kind,
            format!("sha256:{}", "a".repeat(64)),
            "green",
        )
        .unwrap();
        (
            "acquired".into(),
            Some(3),
            Some(fleet),
            Some(ReleaseGenerationName::new(fleet, request.overlay_kind).selector_target()),
            Some(11),
            Some(13),
            Some(serde_json::to_value(intent).unwrap()),
            Some(serde_json::to_value(identity).unwrap()),
            Some(1),
        )
    }

    #[test]
    fn claim_parser_is_closed_and_binds_exact_intent() {
        let request = request();
        assert!(
            parse_claim(&request, acquired_row(&request))
                .unwrap()
                .claim
                .is_some()
        );
        let mut hostile = acquired_row(&request);
        hostile
            .7
            .as_mut()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("overlay_kind".into(), Value::String("maintenance".into()));
        assert!(parse_claim(&request, hostile).is_err());
        let mut refusal = acquired_row(&request);
        refusal.0 = "busy".into();
        refusal.1 = None;
        refusal.6 = None;
        refusal.7 = None;
        assert!(parse_claim(&request, refusal).is_ok());
        let mut ineligible = acquired_row(&request);
        ineligible.0 = "ineligible".into();
        ineligible.1 = None;
        assert!(parse_claim(&request, ineligible).is_ok());
    }

    #[test]
    fn release_retention_cursor_order_is_explicit_and_matches_sql() {
        assert!(
            overlay_kind_rank(ReleaseOverlayKind::Candidate)
                < overlay_kind_rank(ReleaseOverlayKind::Maintenance)
        );
        let migration = include_str!("../../migrations/0038_release_generation_retention.sql");
        assert!(migration.contains("case s.overlay_kind when 'candidate' then 0 else 1 end"));
        assert!(migration.contains("case p_after_overlay_kind when 'candidate' then 0 else 1 end"));
    }

    #[test]
    fn database_surface_and_evidence_are_exact_and_private() {
        let source = include_str!("release_route_retention_db.rs");
        for signature in [
            "discover_fleet_release_generation_retention_candidates($1,$2,$3)",
            "claim_fleet_release_generation_retention($1,$2,$3,$4,$5)",
            "renew_fleet_release_generation_retention_claim($1,$2,$3,$4,$5,$6)",
            "finish_fleet_release_generation_retention($1,$2,$3,$4,$5,$6,$7)",
        ] {
            assert!(source.contains(signature));
        }
        for (field, value) in [
            ("claim_token", "=%"),
            ("expected_identity", "=%"),
            ("expected_intent", "=%"),
            ("selector", "=%"),
        ] {
            assert!(!source.contains(&format!("{field}{value}")));
        }
        let evidence = serde_json::to_value(ReleaseGenerationRetentionEvidence {
            protocol_version: 1,
            driver_operation_id: Uuid::new_v4(),
            overlay_kind: "candidate",
            claim_fence: 7,
            resolution: "already_absent",
            selector: "generations/release-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-candidate",
            expected_intent: &serde_json::json!({}),
            expected_identity: &serde_json::json!({}),
            observed_current_selector: "generations/boot-live",
            observed_current_identity: &Value::Null,
            target_present: false,
            observed_target_device: None,
            observed_target_inode: None,
            mismatch_kind: None,
            observed_target_identity: &Value::Null,
        })
        .unwrap();
        assert_eq!(evidence.as_object().unwrap().len(), 15);
    }
}
