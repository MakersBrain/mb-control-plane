//! Cross-repository compatibility: this client against a real Odoo bridge.
//!
//! Migration plan section 4.6. The `/mb_control/v1` provider lives in
//! `MakersBrain/mb-odoo-addons` and this is its only client. Since the split,
//! each repository's CI can be entirely green while the two disagree: the
//! generated contract in the provider catches a route being renamed or losing
//! `auth="public"`, but nothing catches a field changing meaning, an error
//! status moving, or an idempotency key stopping being honoured.
//!
//! This boots the candidate Odoo image and drives the real `OdooClient` against
//! it. Unit tests on either side are not a substitute, because both sides'
//! unit tests are written against the same assumption -- and it is the
//! assumption that drifts.
//!
//! Ignored by default; it needs an Odoo. Run it with:
//!
//!     MB_ODOO_BASE_URL=http://localhost:8069 \
//!     MB_ODOO_BOOTSTRAP_TOKEN=... \
//!     cargo test --test bridge_compatibility -- --ignored --test-threads=1
//!
//! `--test-threads=1` is not incidental: these share one tenant and run in
//! sequence, because bootstrap must precede everything and the replay
//! assertions depend on what ran before them.

use makersbrain_control_plane::domain::IntegrationError;
use makersbrain_control_plane::integrations::odoo::{
    EntitlementCommand, ErasureReplayCommand, MembershipCommand, ModuleEnableCommand,
    ModuleRestrictCommand, OdooClient, PrivacyExportCommand, TenantBootstrapCommand,
};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

/// A tenant credential of the shape the provider demands: 48-128 alphanumeric.
fn tenant_token() -> String {
    // Deterministic per run, from a UUID so repeated runs do not collide on a
    // tenant that a previous run already bootstrapped.
    Uuid::new_v4().simple().to_string().repeat(2)
}

struct Harness {
    base_url: String,
    bootstrap_token: String,
}

impl Harness {
    fn from_env() -> Option<Self> {
        let base_url = std::env::var("MB_ODOO_BASE_URL").ok()?;
        let bootstrap_token = std::env::var("MB_ODOO_BOOTSTRAP_TOKEN").ok()?;
        Some(Self {
            base_url,
            bootstrap_token,
        })
    }

    fn client(&self, token: &str) -> OdooClient {
        OdooClient::new(&self.base_url, token, None, Duration::from_secs(60))
            .expect("the bridge client rejected its own configuration")
    }
}

/// Skipping silently would make an absent Odoo look like a passing lane, which
/// is the failure this whole test exists to prevent. CI sets both variables;
/// a developer without them gets told why nothing ran.
fn harness() -> Harness {
    Harness::from_env().expect(
        "MB_ODOO_BASE_URL and MB_ODOO_BOOTSTRAP_TOKEN are required. \
         This lane is meaningless without a real bridge to talk to.",
    )
}

/// One bootstrapped tenant, shared by the tests that follow.
async fn bootstrapped(harness: &Harness) -> (OdooClient, Uuid, String) {
    let workshop_id = Uuid::new_v4();
    let token = tenant_token();
    let bootstrap = harness.client(&harness.bootstrap_token);

    let command = TenantBootstrapCommand {
        operation_key: Uuid::new_v4().to_string(),
        workshop_id,
        oidc_client_id: format!("mb-{}", workshop_id.simple()),
        // The provider accepts this scheme specifically so a bridge can be
        // exercised without terminating TLS.
        oidc_issuer: "http://rauthy.localhost:8080".into(),
        bridge_token: token.clone(),
        public_hostname: format!("w{}.makersbrain.test", workshop_id.simple()),
    };

    bootstrap
        .bootstrap_tenant(&command)
        .await
        .expect("tenant bootstrap failed against the real bridge");

    (harness.client(&token), workshop_id, token)
}

#[tokio::test]
#[ignore = "needs a running Odoo bridge"]
async fn the_bridge_reports_itself_ready_and_names_its_tenant() {
    let harness = harness();
    let (client, workshop_id, _) = bootstrapped(&harness).await;

    let health = client.health().await.expect("health call failed");
    assert_eq!(health.status, "ready", "bridge is not ready: {health:?}");
    assert!(!health.database.is_empty(), "health names no database");
    assert_eq!(
        health.workshop_id.as_deref(),
        Some(workshop_id.to_string().as_str()),
        "the bridge serves a different tenant than the one just bootstrapped",
    );
}

#[tokio::test]
#[ignore = "needs a running Odoo bridge"]
async fn a_wrong_credential_is_rejected_rather_than_ignored() {
    let harness = harness();
    let (_, _, _) = bootstrapped(&harness).await;

    // Well-formed and of the right shape, but not the tenant's.
    let impostor = harness.client(&tenant_token());
    match impostor.health().await {
        Err(IntegrationError::Rejected) => {}
        Err(other) => panic!("a wrong credential produced {other:?}, expected Rejected"),
        Ok(health) => panic!("a wrong credential was accepted: {health:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a running Odoo bridge"]
async fn a_replayed_operation_key_returns_the_first_result() {
    let harness = harness();
    let workshop_id = Uuid::new_v4();
    let token = tenant_token();
    let bootstrap = harness.client(&harness.bootstrap_token);

    let command = TenantBootstrapCommand {
        operation_key: Uuid::new_v4().to_string(),
        workshop_id,
        oidc_client_id: format!("mb-{}", workshop_id.simple()),
        oidc_issuer: "http://rauthy.localhost:8080".into(),
        bridge_token: token,
        public_hostname: format!("w{}.makersbrain.test", workshop_id.simple()),
    };

    let first = bootstrap
        .bootstrap_tenant(&command)
        .await
        .expect("bootstrap");
    // The control plane retries on an unknown outcome. If a replay did work
    // twice, a network blip would silently provision a tenant twice.
    let replayed = bootstrap
        .bootstrap_tenant(&command)
        .await
        .expect("replaying the same operation key failed");
    assert_eq!(
        first, replayed,
        "the same operation key produced a different result on replay",
    );
}

#[tokio::test]
#[ignore = "needs a running Odoo bridge"]
async fn membership_reconciliation_round_trips() {
    let harness = harness();
    let (client, workshop_id, _) = bootstrapped(&harness).await;

    let command = MembershipCommand {
        operation_key: Uuid::new_v4().to_string(),
        workshop_id,
        user_id: Uuid::new_v4(),
        subject: Uuid::new_v4().to_string(),
        email: "compatibility@makersbrain.test".into(),
        name: "Compatibility Lane".into(),
        role: "member".into(),
        epoch: 1,
        active: true,
    };
    let applied = client
        .reconcile_membership(&command)
        .await
        .expect("membership reconciliation failed against the real bridge");
    assert!(
        applied.applied,
        "the bridge accepted the call but reported the member unapplied",
    );
}

#[tokio::test]
#[ignore = "needs a running Odoo bridge"]
async fn an_entitlement_is_applied_and_reports_whether_it_was_stale() {
    let harness = harness();
    let (client, workshop_id, _) = bootstrapped(&harness).await;

    let command = EntitlementCommand {
        operation_key: Uuid::new_v4().to_string(),
        workshop_id,
        version: 2,
        plan: "studio".into(),
        status: "active".into(),
        limits: json!({}),
        expires_at: None,
        signature: String::new(),
    };
    let applied = client
        .apply_entitlement(&command)
        .await
        .expect("entitlement application failed");
    assert!(applied.applied, "the bridge refused a first entitlement");

    // An older version must be reported stale rather than silently applied:
    // the control plane relies on that to detect out-of-order delivery.
    let stale = EntitlementCommand {
        operation_key: Uuid::new_v4().to_string(),
        workshop_id,
        version: 1,
        plan: "studio".into(),
        status: "active".into(),
        limits: json!({}),
        expires_at: None,
        signature: String::new(),
    };
    let outcome = client
        .apply_entitlement(&stale)
        .await
        .expect("a stale entitlement should be answered, not refused");
    assert!(
        outcome.stale || !outcome.applied,
        "an older entitlement version was applied without being marked stale",
    );
}

#[tokio::test]
#[ignore = "needs a running Odoo bridge"]
async fn module_activation_and_restriction_are_accepted() {
    let harness = harness();
    let (client, workshop_id, _) = bootstrapped(&harness).await;

    client
        .enable_modules(&ModuleEnableCommand {
            operation_key: Uuid::new_v4().to_string(),
            workshop_id,
            module_key: "ceramics".into(),
            modules: vec!["mb_ceramics_base".into()],
        })
        .await
        .expect("module activation failed against the real bridge");

    client
        .restrict_modules(&ModuleRestrictCommand {
            operation_key: Uuid::new_v4().to_string(),
            workshop_id,
            module_key: "ceramics".into(),
            modules: vec!["mb_ceramics_base".into()],
            reason: "compatibility lane".into(),
        })
        .await
        .expect("module restriction failed against the real bridge");
}

#[tokio::test]
#[ignore = "needs a running Odoo bridge"]
async fn invoice_and_inventory_capture_are_reachable() {
    let harness = harness();
    let (client, workshop_id, _) = bootstrapped(&harness).await;

    // Shape only: these carry documents in production. What is under test is
    // that the route exists, authenticates, and answers in the agreed envelope
    // rather than an HTML error page.
    let invoice = json!({
        "operation_key": Uuid::new_v4().to_string(),
        "workshop_id": workshop_id,
        "documents": [],
    });
    match client.capture_invoice(&invoice).await {
        Ok(_) => {}
        // A refusal on an empty document set is a legitimate answer; an
        // unreachable or undecodable route is not.
        Err(IntegrationError::Rejected) => {}
        Err(other) => panic!("invoice capture is not usable: {other:?}"),
    }

    let inventory = json!({
        "operation_key": Uuid::new_v4().to_string(),
        "workshop_id": workshop_id,
        "results": [],
    });
    match client.capture_inventory_result(&inventory).await {
        Ok(_) | Err(IntegrationError::Rejected) => {}
        Err(other) => panic!("inventory capture is not usable: {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a running Odoo bridge"]
async fn privacy_export_and_erasure_replay_are_reachable() {
    let harness = harness();
    let (client, workshop_id, _) = bootstrapped(&harness).await;

    // Privacy operations are legally load-bearing: a route that has moved must
    // fail here, loudly, and not the first time a subject exercises a right.
    match client
        .export_personal_data(&PrivacyExportCommand {
            workshop_id,
            user_id: Uuid::new_v4(),
        })
        .await
    {
        Ok(_) | Err(IntegrationError::Rejected) => {}
        Err(other) => panic!("privacy export is not usable: {other:?}"),
    }

    match client
        .replay_erasure(&ErasureReplayCommand {
            operation_key: Uuid::new_v4().to_string(),
            workshop_id,
            user_id: Uuid::new_v4(),
            subject_key: Uuid::new_v4(),
        })
        .await
    {
        Ok(()) | Err(IntegrationError::Rejected) => {}
        Err(other) => panic!("erasure replay is not usable: {other:?}"),
    }
}
