//! Dormant typed database capability for immutable route-set retention.
#![allow(dead_code)]

use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use super::DriverError;
use super::gateway::{RouteSetGenerationIdentity, RouteSetPublicationKind};
use super::route_generation_fs::validate_selector_target;
use super::route_set_generation_fs::{
    MAX_ROUTES, RouteSetGenerationIntent, RouteSetGenerationName,
    validate_retention_generation_authority,
};

const MIN_TTL_SECONDS: i32 = 30;
const MAX_TTL_SECONDS: i32 = 3_600;
const MAX_DISCOVERY: i32 = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RouteSetRetentionCandidate {
    pub publication_id: Uuid,
    pub publication_kind: RouteSetPublicationKind,
    pub selector: String,
    pub retention_not_before: OffsetDateTime,
}

#[derive(Clone)]
pub(super) struct RouteSetRetentionClaimRequest {
    pub publication_id: Uuid,
    pub instance_owner: Uuid,
    pub claim_token: Uuid,
    pub ttl_seconds: i32,
}

#[derive(Clone)]
pub(super) struct RouteSetRetentionClaim {
    pub publication_id: Uuid,
    pub instance_owner: Uuid,
    pub claim_token: Uuid,
    pub ttl_seconds: i32,
    pub claim_fence: i64,
    pub publication_kind: RouteSetPublicationKind,
    pub selector: String,
    pub directory_device: u64,
    pub directory_inode: u64,
    pub expected_intent: Value,
    pub expected_identity: Value,
    pub intent: RouteSetGenerationIntent,
    pub identity: RouteSetGenerationIdentity,
    pub route_count: usize,
    pub present_count: usize,
}

impl RouteSetRetentionClaim {
    pub(super) fn filesystem_intent(&self) -> Result<RouteSetGenerationIntent, DriverError> {
        Ok(self.intent.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClaimRouteSetRetentionOutcome {
    Acquired,
    Replay,
    Busy,
    Ineligible,
    NotFound,
    Invalid,
}

pub(super) struct ClaimRouteSetRetention {
    pub outcome: ClaimRouteSetRetentionOutcome,
    pub claim: Option<RouteSetRetentionClaim>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RouteSetRetentionResolution {
    Deleted,
    AlreadyAbsent,
    ProtectedCurrent,
    IdentityMismatch,
}

impl RouteSetRetentionResolution {
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
pub(super) struct RouteSetRetentionEvidence<'a> {
    pub protocol_version: u8,
    pub publication_id: Uuid,
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
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<Value>,
    Option<Value>,
    Option<i32>,
    Option<i32>,
);

pub(super) async fn discover_retention_candidates(
    ledger: &PgPool,
    after: Option<Uuid>,
    limit: i32,
) -> Result<Vec<RouteSetRetentionCandidate>, DriverError> {
    if !(1..=MAX_DISCOVERY).contains(&limit) {
        return Err(invalid("retention discovery limit is invalid"));
    }
    let rows: Vec<(Uuid, String, String, OffsetDateTime)> = sqlx::query_as(
        "select publication_id,publication_kind,selector,retention_not_before
           from control.discover_route_set_generation_retention_candidates($1,$2)",
    )
    .bind(after)
    .bind(limit)
    .fetch_all(ledger)
    .await
    .map_err(DriverError::internal)?;
    let mut previous = after;
    rows.into_iter()
        .map(|(publication_id, kind, selector, retention_not_before)| {
            if publication_id.is_nil()
                || previous.is_some_and(|prior| prior >= publication_id)
                || validate_selector_target(&selector).is_err()
            {
                return Err(invalid("retention discovery row is malformed"));
            }
            let publication_kind = parse_kind(&kind)?;
            if selector
                != RouteSetGenerationName::new(publication_id, publication_kind).selector_target()
            {
                return Err(invalid("retention discovery selector differs"));
            }
            previous = Some(publication_id);
            Ok(RouteSetRetentionCandidate {
                publication_id,
                publication_kind,
                selector,
                retention_not_before,
            })
        })
        .collect()
}

#[tracing::instrument(
    name = "deployment_driver.route_set_retention.claim_dormant",
    skip_all,
    fields(publication.id=%request.publication_id, retention.outcome=tracing::field::Empty)
)]
pub(super) async fn claim_retention(
    ledger: &PgPool,
    request: &RouteSetRetentionClaimRequest,
) -> Result<ClaimRouteSetRetention, DriverError> {
    validate_request(request)?;
    let row: ClaimRow = sqlx::query_as(
        "select outcome,claim_fence,publication_kind,selector,directory_device,directory_inode,
                expected_intent,expected_identity,route_count,present_count
           from control.claim_route_set_generation_retention($1,$2,$3,$4)",
    )
    .bind(request.publication_id)
    .bind(request.instance_owner)
    .bind(request.claim_token)
    .bind(request.ttl_seconds)
    .fetch_one(ledger)
    .await
    .map_err(DriverError::internal)?;
    tracing::Span::current().record("retention.outcome", row.0.as_str());
    parse_claim(request, row)
}

pub(super) async fn renew_retention_claim(
    ledger: &PgPool,
    claim: &RouteSetRetentionClaim,
) -> Result<bool, DriverError> {
    sqlx::query_scalar("select control.renew_route_set_generation_retention_claim($1,$2,$3,$4,$5)")
        .bind(claim.publication_id)
        .bind(claim.instance_owner)
        .bind(claim.claim_token)
        .bind(claim.claim_fence)
        .bind(claim.ttl_seconds)
        .fetch_one(ledger)
        .await
        .map_err(DriverError::internal)
}

#[tracing::instrument(
    name = "deployment_driver.route_set_retention.finish_dormant",
    skip_all,
    fields(publication.id=%claim.publication_id, retention.resolution=resolution.as_str(),
        retention.outcome=tracing::field::Empty)
)]
pub(super) async fn finish_retention(
    ledger: &PgPool,
    claim: &RouteSetRetentionClaim,
    resolution: RouteSetRetentionResolution,
    evidence: &RouteSetRetentionEvidence<'_>,
) -> Result<String, DriverError> {
    let evidence = serde_json::to_value(evidence).map_err(DriverError::internal)?;
    let outcome: String = sqlx::query_scalar(
        "select control.finish_route_set_generation_retention($1,$2,$3,$4,$5,$6)",
    )
    .bind(claim.publication_id)
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
        Err(invalid("retention finish outcome is not closed"))
    }
}

fn parse_claim(
    request: &RouteSetRetentionClaimRequest,
    row: ClaimRow,
) -> Result<ClaimRouteSetRetention, DriverError> {
    let outcome = match row.0.as_str() {
        "acquired" => ClaimRouteSetRetentionOutcome::Acquired,
        "replay" => ClaimRouteSetRetentionOutcome::Replay,
        "busy" => ClaimRouteSetRetentionOutcome::Busy,
        "ineligible" => ClaimRouteSetRetentionOutcome::Ineligible,
        "not_found" => ClaimRouteSetRetentionOutcome::NotFound,
        "invalid" => ClaimRouteSetRetentionOutcome::Invalid,
        _ => return Err(invalid("retention claim outcome is invalid")),
    };
    if matches!(
        outcome,
        ClaimRouteSetRetentionOutcome::Acquired | ClaimRouteSetRetentionOutcome::Replay
    ) {
        return Ok(ClaimRouteSetRetention {
            outcome,
            claim: Some(parse_acquired_claim(request, row)?),
        });
    }
    let exact_shape = match outcome {
        ClaimRouteSetRetentionOutcome::Invalid | ClaimRouteSetRetentionOutcome::NotFound => {
            row.1.is_none()
                && row.2.is_none()
                && row.3.is_none()
                && row.4.is_none()
                && row.5.is_none()
                && row.6.is_none()
                && row.7.is_none()
                && row.8.is_none()
                && row.9.is_none()
        }
        ClaimRouteSetRetentionOutcome::Busy => {
            row.1.is_none()
                && row.2.is_some()
                && row.3.is_some()
                && row.4.is_some()
                && row.5.is_some()
                && row.6.is_none()
                && row.7.is_none()
                && row.8.is_some()
                && row.9.is_some()
        }
        ClaimRouteSetRetentionOutcome::Ineligible => {
            row.1.is_none()
                && row.2.is_some()
                && row.3.is_some()
                && row.4.is_some()
                && row.5.is_some()
                && row.6.is_some()
                && row.7.is_some()
                && row.8.is_some()
                && row.9.is_some()
        }
        ClaimRouteSetRetentionOutcome::Acquired | ClaimRouteSetRetentionOutcome::Replay => false,
    };
    if !exact_shape {
        return Err(invalid("retention refusal row shape is invalid"));
    }
    match outcome {
        ClaimRouteSetRetentionOutcome::Busy => validate_refusal_summary(request, &row)?,
        ClaimRouteSetRetentionOutcome::Ineligible => {
            let mut authenticated = row.clone();
            authenticated.0 = "acquired".into();
            authenticated.1 = Some(1);
            parse_acquired_claim(request, authenticated)?;
        }
        ClaimRouteSetRetentionOutcome::Invalid | ClaimRouteSetRetentionOutcome::NotFound => {}
        ClaimRouteSetRetentionOutcome::Acquired | ClaimRouteSetRetentionOutcome::Replay => {
            unreachable!("authority outcomes returned above")
        }
    }
    Ok(ClaimRouteSetRetention {
        outcome,
        claim: None,
    })
}

fn validate_refusal_summary(
    request: &RouteSetRetentionClaimRequest,
    row: &ClaimRow,
) -> Result<(), DriverError> {
    let kind = parse_kind(
        row.2
            .as_deref()
            .ok_or_else(|| invalid("retention refusal kind is absent"))?,
    )?;
    let selector = row
        .3
        .as_deref()
        .ok_or_else(|| invalid("retention refusal selector is absent"))?;
    positive_u64(row.4, "refusal directory device")?;
    positive_u64(row.5, "refusal directory inode")?;
    let route_count = bounded_count(row.8, "refusal route count")?;
    let present_count = bounded_count(row.9, "refusal present count")?;
    if present_count > route_count
        || selector != RouteSetGenerationName::new(request.publication_id, kind).selector_target()
    {
        return Err(invalid("retention refusal summary differs"));
    }
    Ok(())
}

fn parse_acquired_claim(
    request: &RouteSetRetentionClaimRequest,
    row: ClaimRow,
) -> Result<RouteSetRetentionClaim, DriverError> {
    let claim_fence = row
        .1
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid("retention claim fence is invalid"))?;
    let publication_kind = parse_kind(
        row.2
            .as_deref()
            .ok_or_else(|| invalid("retention kind is absent"))?,
    )?;
    let selector = row
        .3
        .clone()
        .ok_or_else(|| invalid("retention selector is absent"))?;
    let directory_device = positive_u64(row.4, "directory device")?;
    let directory_inode = positive_u64(row.5, "directory inode")?;
    let expected_intent = row
        .6
        .clone()
        .ok_or_else(|| invalid("retention expected intent is absent"))?;
    let intent: RouteSetGenerationIntent = serde_json::from_value(expected_intent.clone())
        .map_err(|_| invalid("retention expected intent is malformed"))?;
    let expected_identity = row
        .7
        .clone()
        .ok_or_else(|| invalid("retention expected identity is absent"))?;
    let identity: RouteSetGenerationIdentity = serde_json::from_value(expected_identity.clone())
        .map_err(|_| invalid("retention expected identity is malformed"))?;
    let route_count = bounded_count(row.8, "route count")?;
    let present_count = bounded_count(row.9, "present count")?;
    validate_retention_generation_authority(&intent, &identity).map_err(DriverError::internal)?;
    if present_count > route_count
        || intent.publication_id != request.publication_id
        || intent.publication_kind != publication_kind
        || identity.publication_id != request.publication_id
        || identity.publication_kind != publication_kind
        || selector
            != RouteSetGenerationName::new(request.publication_id, publication_kind)
                .selector_target()
    {
        return Err(invalid("retention claim identity differs"));
    }
    Ok(RouteSetRetentionClaim {
        publication_id: request.publication_id,
        instance_owner: request.instance_owner,
        claim_token: request.claim_token,
        ttl_seconds: request.ttl_seconds,
        claim_fence,
        publication_kind,
        selector,
        directory_device,
        directory_inode,
        expected_intent,
        expected_identity,
        intent,
        identity,
        route_count,
        present_count,
    })
}

fn validate_request(request: &RouteSetRetentionClaimRequest) -> Result<(), DriverError> {
    if request.publication_id.is_nil()
        || request.instance_owner.is_nil()
        || request.claim_token.is_nil()
        || !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&request.ttl_seconds)
    {
        return Err(invalid("retention claim request is invalid"));
    }
    Ok(())
}

fn parse_kind(value: &str) -> Result<RouteSetPublicationKind, DriverError> {
    serde_json::from_value(Value::String(value.to_owned()))
        .map_err(|_| invalid("retention publication kind is invalid"))
}

fn positive_u64(value: Option<i64>, description: &str) -> Result<u64, DriverError> {
    value
        .and_then(|value| u64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| invalid(format!("retention {description} is invalid")))
}

fn bounded_count(value: Option<i32>, description: &str) -> Result<usize, DriverError> {
    value
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value <= MAX_ROUTES)
        .ok_or_else(|| invalid(format!("retention {description} is invalid")))
}

fn invalid(message: impl Into<String>) -> DriverError {
    DriverError::internal(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(publication_id: Uuid) -> RouteSetRetentionClaimRequest {
        RouteSetRetentionClaimRequest {
            publication_id,
            instance_owner: Uuid::new_v4(),
            claim_token: Uuid::new_v4(),
            ttl_seconds: 90,
        }
    }

    fn acquired_row(request: &RouteSetRetentionClaimRequest) -> ClaimRow {
        let workshop_id = Uuid::new_v4();
        let intent = RouteSetGenerationIntent::new(
            request.publication_id,
            RouteSetPublicationKind::Projection,
            17,
            workshop_id,
            19,
        )
        .unwrap();
        let identity = RouteSetGenerationIdentity::new(
            request.publication_id,
            RouteSetPublicationKind::Projection,
            17,
            workshop_id,
            19,
            format!("sha256:{}", "a".repeat(64)),
        )
        .unwrap();
        (
            "acquired".into(),
            Some(23),
            Some("projection".into()),
            Some(
                RouteSetGenerationName::new(
                    request.publication_id,
                    RouteSetPublicationKind::Projection,
                )
                .selector_target(),
            ),
            Some(29),
            Some(31),
            Some(serde_json::to_value(intent).unwrap()),
            Some(serde_json::to_value(identity).unwrap()),
            Some(2),
            Some(1),
        )
    }

    #[test]
    fn claim_parser_accepts_only_exact_filesystem_intent_and_identity() {
        let request = request(Uuid::new_v4());
        let parsed = parse_claim(&request, acquired_row(&request)).unwrap();
        let claim = parsed.claim.unwrap();
        assert_eq!(claim.filesystem_intent().unwrap(), claim.intent);

        let mut hostile = acquired_row(&request);
        hostile.6.as_mut().unwrap().as_object_mut().unwrap().insert(
            "selector".into(),
            Value::String("generations/boot-live".into()),
        );
        assert!(parse_claim(&request, hostile).is_err());
    }

    #[test]
    fn refusal_rows_have_closed_outcome_specific_shapes() {
        let request = request(Uuid::new_v4());
        let empty = |outcome: &str| {
            (
                outcome.into(),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )
        };
        assert!(parse_claim(&request, empty("invalid")).is_ok());
        assert!(parse_claim(&request, empty("not_found")).is_ok());
        let mut busy = acquired_row(&request);
        busy.0 = "busy".into();
        busy.1 = None;
        busy.6 = None;
        busy.7 = None;
        assert!(parse_claim(&request, busy.clone()).is_ok());
        busy.6 = Some(Value::Null);
        assert!(parse_claim(&request, busy).is_err());
        let mut ineligible = acquired_row(&request);
        ineligible.0 = "ineligible".into();
        ineligible.1 = None;
        assert!(parse_claim(&request, ineligible).is_ok());
    }

    #[test]
    fn database_surface_and_evidence_are_exact_and_privacy_safe() {
        let source = include_str!("route_set_retention_db.rs");
        for signature in [
            "discover_route_set_generation_retention_candidates($1,$2)",
            "claim_route_set_generation_retention($1,$2,$3,$4)",
            "renew_route_set_generation_retention_claim($1,$2,$3,$4,$5)",
            "finish_route_set_generation_retention($1,$2,$3,$4,$5,$6)",
        ] {
            assert!(source.contains(signature));
        }
        for (left, right) in [
            ("retention.", "selector"),
            ("claim_token", "=%"),
            ("expected_identity", "=%"),
            ("expected_intent", "=%"),
            ("route_set_digest", "=%"),
        ] {
            assert!(!source.contains(&format!("{left}{right}")));
        }
        let evidence = serde_json::to_value(RouteSetRetentionEvidence {
            protocol_version: 1,
            publication_id: Uuid::new_v4(),
            claim_fence: 7,
            resolution: "already_absent",
            selector: "generations/route-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-projection",
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
        assert_eq!(evidence.as_object().unwrap().len(), 14);
    }
}
