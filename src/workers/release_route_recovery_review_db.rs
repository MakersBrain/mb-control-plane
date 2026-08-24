//! Dormant release-worker boundary for independently reviewing immutable
//! interrupted-release runtime and route evidence.
#![allow(dead_code)]

use uuid::Uuid;

use crate::domain::IntegrationError;
use crate::persistence::{LeasedOperation, Store};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReleaseRecoveryReviewDecision {
    AcceptCandidate,
    KeepQuarantined,
}

impl ReleaseRecoveryReviewDecision {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AcceptCandidate => "accept_candidate",
            Self::KeepQuarantined => "keep_quarantined",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ReviewReleaseRecovery {
    Approved(String),
    KeptQuarantined(String),
    Replay(String),
    ObservationAbsent,
    ResolutionAbsent,
    LeaseLost,
    StateDrift,
    Conflict,
}

impl ReviewReleaseRecovery {
    const fn trace_outcome(&self) -> &'static str {
        match self {
            Self::Approved(_) => "approved",
            Self::KeptQuarantined(_) => "kept_quarantined",
            Self::Replay(_) => "replay",
            Self::ObservationAbsent => "observation_absent",
            Self::ResolutionAbsent => "resolution_absent",
            Self::LeaseLost => "lease_lost",
            Self::StateDrift => "state_drift",
            Self::Conflict => "conflict",
        }
    }
}

#[tracing::instrument(
    name = "release_worker.release_route_recovery.review_dormant",
    skip_all,
    fields(
        driver.operation_id = %driver_operation_id,
        review.decision = decision.as_str(),
        review.outcome = tracing::field::Empty
    )
)]
pub(super) async fn review_interrupted_release_runtime_observation(
    store: &Store,
    operation: &LeasedOperation,
    driver_operation_id: Uuid,
    claim_fence: i64,
    observation_digest: &str,
    decision: ReleaseRecoveryReviewDecision,
) -> Result<ReviewReleaseRecovery, IntegrationError> {
    if operation.id.is_nil()
        || operation.kind != "odoo.release.adopt"
        || operation.workshop_id.is_some()
        || operation.attempt <= 0
        || operation.leased_by.trim().is_empty()
        || driver_operation_id.is_nil()
        || claim_fence <= 0
        || !digest(observation_digest)
    {
        return Err(IntegrationError::ContractDrift);
    }
    let row: (String, Option<String>) = sqlx::query_as(
        "select outcome,review_digest
         from control.review_interrupted_immutable_release_runtime_observation(
          $1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(driver_operation_id)
    .bind(claim_fence)
    .bind(operation.id)
    .bind(operation.attempt)
    .bind(&operation.leased_by)
    .bind(observation_digest)
    .bind(decision.as_str())
    .fetch_one(store.pool())
    .await
    .map_err(|_| IntegrationError::Unavailable)?;
    let parsed = parse_review(row);
    tracing::Span::current().record(
        "review.outcome",
        parsed
            .as_ref()
            .map_or("contract_drift", ReviewReleaseRecovery::trace_outcome),
    );
    parsed
}

fn parse_review(row: (String, Option<String>)) -> Result<ReviewReleaseRecovery, IntegrationError> {
    match (row.0.as_str(), row.1) {
        ("approved", Some(value)) if digest(&value) => Ok(ReviewReleaseRecovery::Approved(value)),
        ("kept_quarantined", Some(value)) if digest(&value) => {
            Ok(ReviewReleaseRecovery::KeptQuarantined(value))
        }
        ("replay", Some(value)) if digest(&value) => Ok(ReviewReleaseRecovery::Replay(value)),
        ("observation_absent", None) => Ok(ReviewReleaseRecovery::ObservationAbsent),
        ("resolution_absent", None) => Ok(ReviewReleaseRecovery::ResolutionAbsent),
        ("lease_lost", None) => Ok(ReviewReleaseRecovery::LeaseLost),
        ("state_drift", None) => Ok(ReviewReleaseRecovery::StateDrift),
        ("conflict", None) => Ok(ReviewReleaseRecovery::Conflict),
        _ => Err(IntegrationError::ContractDrift),
    }
}

fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_outcomes_are_closed_and_digest_strict() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            parse_review(("approved".into(), Some(digest.clone()))).unwrap(),
            ReviewReleaseRecovery::Approved(digest)
        );
        assert!(parse_review(("approved".into(), None)).is_err());
        assert!(parse_review(("future".into(), None)).is_err());
        assert!(parse_review(("replay".into(), Some("sha256:bad".into()))).is_err());
    }

    #[test]
    fn review_tracing_uses_only_closed_parsed_outcomes() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let outcomes = [
            ReviewReleaseRecovery::Approved(digest.clone()),
            ReviewReleaseRecovery::KeptQuarantined(digest.clone()),
            ReviewReleaseRecovery::Replay(digest),
            ReviewReleaseRecovery::ObservationAbsent,
            ReviewReleaseRecovery::ResolutionAbsent,
            ReviewReleaseRecovery::LeaseLost,
            ReviewReleaseRecovery::StateDrift,
            ReviewReleaseRecovery::Conflict,
        ];
        assert_eq!(
            outcomes.each_ref().map(|outcome| outcome.trace_outcome()),
            [
                "approved",
                "kept_quarantined",
                "replay",
                "observation_absent",
                "resolution_absent",
                "lease_lost",
                "state_drift",
                "conflict",
            ]
        );

        let source = include_str!("release_route_recovery_review_db.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(!production.contains("record(\"review.outcome\", row.0"));
        assert!(production.contains("contract_drift"));
    }

    #[test]
    fn module_is_private_and_has_no_active_callsite() {
        let root = include_str!("mod.rs");
        assert_eq!(
            root.matches("mod release_route_recovery_review_db;")
                .count(),
            1
        );
        assert_eq!(
            root.matches("release_route_recovery_review_db::").count(),
            0
        );
    }
}
