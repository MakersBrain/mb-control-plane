//! Cross-repository compatibility: this client against a real Odoo bridge.
//!
//! The retained `/mb_control/v1` provider contract lives in
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
//! `--test-threads=1` is not incidental. A database holds one company, and the
//! first bootstrap sets that company's credential verifier -- from then on the
//! shared environment token is refused. So the suite bootstraps exactly once
//! and every test shares that tenant.
//!
//! Note the direction: one database serves one workshop, but a workshop is not
//! limited to one database. `control.odoo_databases` allows exactly one
//! `primary` per workshop and any number of `duplicate` rows for snapshots and
//! restores, each with its own `source_database_id`. This lane exercises a
//! single database, which is the unit the bridge authenticates against.

use mb_control_plane::domain::IntegrationError;
use mb_control_plane::integrations::odoo::{
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

/// The one tenant this database serves. The workshop may have other databases
/// -- duplicates taken for snapshots or restores -- but each is bootstrapped
/// separately and holds its own credential verifier.
struct Tenant {
    workshop_id: Uuid,
    token: String,
    /// The bootstrap command that created it, kept so the replay test can send
    /// the identical request again.
    command: TenantBootstrapCommand,
    first_response: serde_json::Value,
}

static TENANT: tokio::sync::OnceCell<Tenant> = tokio::sync::OnceCell::const_new();

/// Bootstrap once, then share. A second bootstrap of *this* database with the
/// environment token would be refused, because its company now has its own
/// credential verifier -- which is the behaviour, not a limitation of the test.
async fn tenant(harness: &Harness) -> &'static Tenant {
    TENANT
        .get_or_init(|| async {
            let workshop_id = Uuid::new_v4();
            let token = tenant_token();
            let command = TenantBootstrapCommand {
                operation_key: Uuid::new_v4().to_string(),
                workshop_id,
                oidc_client_id: format!("mb-{}", workshop_id.simple()),
                // The provider accepts this scheme specifically so a bridge can
                // be exercised without terminating TLS.
                oidc_issuer: "http://rauthy.localhost:8080".into(),
                bridge_token: token.clone(),
                public_hostname: format!("w{}.makersbrain.test", workshop_id.simple()),
            };
            let first_response = harness
                .client(&harness.bootstrap_token)
                .bootstrap_tenant(&command)
                .await
                .expect("tenant bootstrap failed against the real bridge");
            Tenant {
                workshop_id,
                token,
                command,
                first_response,
            }
        })
        .await
}

/// A client holding the tenant credential, and the workshop it speaks for.
async fn bootstrapped(harness: &Harness) -> (OdooClient, Uuid, String) {
    let tenant = tenant(harness).await;
    (
        harness.client(&tenant.token),
        tenant.workshop_id,
        tenant.token.clone(),
    )
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
        Err(IntegrationError::Unauthorized) => {}
        Err(other) => panic!("a wrong credential produced {other:?}, expected Unauthorized"),
        Ok(health) => panic!("a wrong credential was accepted: {health:?}"),
    }

    // The shared bootstrap credential must also stop working once the tenant
    // has its own. Otherwise one leaked environment value would reopen every
    // database that ever used it.
    let stale_bootstrap = harness.client(&harness.bootstrap_token);
    match stale_bootstrap.health().await {
        Err(IntegrationError::Unauthorized) => {}
        Err(other) => panic!("the bootstrap credential produced {other:?}"),
        Ok(health) => panic!("the bootstrap credential still works after bootstrap: {health:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a running Odoo bridge"]
async fn a_replayed_operation_key_returns_the_first_result() {
    let harness = harness();
    let tenant = tenant(&harness).await;

    // The identical bootstrap, sent again with the same operation key. The
    // control plane retries on an unknown outcome, so if a replay did the work
    // twice a network blip would provision a tenant twice.
    // Not the bootstrap token: it stopped working the moment the tenant got its
    // own verifier. The tenant credential is accepted here for the same reason.
    let replayed = harness
        .client(&tenant.token)
        .bootstrap_tenant(&tenant.command)
        .await
        .expect("replaying the original operation key was refused");

    assert_eq!(
        tenant.first_response, replayed,
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
        role: "artisan".into(),
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
async fn an_entitlement_applies_once_and_refuses_to_go_backwards() {
    let harness = harness();
    let (client, workshop_id, _) = bootstrapped(&harness).await;

    let entitlement = |key: String, version: i64| EntitlementCommand {
        operation_key: key,
        workshop_id,
        version,
        plan: "studio".into(),
        status: "active".into(),
        limits: json!({}),
        expires_at: None,
        // Stored rather than verified by the provider, but required to be
        // present: an entitlement with no provenance is refused.
        signature: "compatibility-lane-signature".into(),
    };

    let applied = client
        .apply_entitlement(&entitlement(Uuid::new_v4().to_string(), 2))
        .await
        .expect("entitlement application failed");
    assert!(applied.applied, "the bridge refused a first entitlement");

    // The same version with identical data is idempotent, not an error: the
    // control plane redelivers, and a redelivery must not look like a change.
    let repeated = client
        .apply_entitlement(&entitlement(Uuid::new_v4().to_string(), 2))
        .await
        .expect("re-applying an identical entitlement was refused");
    assert!(
        !repeated.applied,
        "an identical redelivery was reported as a fresh application",
    );

    // An older version is refused outright. That is what stops out-of-order
    // delivery quietly downgrading a tenant.
    match client
        .apply_entitlement(&entitlement(Uuid::new_v4().to_string(), 1))
        .await
    {
        Err(IntegrationError::Rejected) => {}
        Err(other) => panic!("an older entitlement produced {other:?}, expected Rejected"),
        Ok(outcome) => panic!("an older entitlement was accepted: {outcome:?}"),
    }
}

#[tokio::test]
#[ignore = "needs a running Odoo bridge"]
async fn a_bundle_is_scheduled_for_install_and_an_installed_one_can_be_restricted() {
    let harness = harness();
    let (client, workshop_id, _) = bootstrapped(&harness).await;

    // Enabling only *schedules* the install. The provider says why in its own
    // comment: installing immediately would commit and rebuild the registry in
    // the middle of the request, before the idempotency receipt is stored. The
    // deployment worker applies "to install" modules afterwards.
    client
        .enable_modules(&ModuleEnableCommand {
            operation_key: Uuid::new_v4().to_string(),
            workshop_id,
            // The provider keeps an exact bundle registry: the key must exist
            // and the member list must equal it, so this is a real contract
            // assertion rather than an arbitrary payload.
            module_key: "firings".into(),
            modules: vec!["mb_ceramics_firing".into()],
        })
        .await
        .expect("module activation failed against the real bridge");

    // Restriction is a different bundle on purpose. It writes record rules
    // against the models a capability *owns*, so it needs one that is actually
    // installed -- and a bundle merely scheduled above has no models yet. The
    // lane installs mb_invoice_capture, so this exercises real enforcement
    // rather than the same scheduling path twice.
    client
        .restrict_modules(&ModuleRestrictCommand {
            operation_key: Uuid::new_v4().to_string(),
            workshop_id,
            module_key: "invoice-capture".into(),
            modules: vec!["mb_invoice_capture".into()],
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
