use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WorkshopRole {
    Viewer,
    Artisan,
    Accountant,
    StudioManager,
    Owner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkshopPermission {
    ViewWorkshop,
    ManageMembers,
    ManageModules,
    ManageDatabase,
    TransferOwnership,
}

impl WorkshopRole {
    pub const INVITABLE: [Self; 4] = [
        Self::Viewer,
        Self::Artisan,
        Self::Accountant,
        Self::StudioManager,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Artisan => "artisan",
            Self::Accountant => "accountant",
            Self::StudioManager => "studio_manager",
            Self::Owner => "owner",
        }
    }

    pub fn can_manage_members(self) -> bool {
        matches!(self, Self::Owner | Self::StudioManager)
    }

    pub fn can_invite(self) -> bool {
        Self::INVITABLE.contains(&self)
    }

    pub fn can_manage_database(self) -> bool {
        self == Self::Owner
    }

    pub fn can_manage_modules(self) -> bool {
        matches!(self, Self::Owner | Self::StudioManager)
    }

    pub fn allows(self, permission: WorkshopPermission) -> bool {
        match permission {
            WorkshopPermission::ViewWorkshop => true,
            WorkshopPermission::ManageMembers => self.can_manage_members(),
            WorkshopPermission::ManageModules => self.can_manage_modules(),
            WorkshopPermission::ManageDatabase => self.can_manage_database(),
            WorkshopPermission::TransferOwnership => self == Self::Owner,
        }
    }
}

pub fn opaque_database_ref(id: uuid::Uuid) -> String {
    format!("mb_{}", id.simple())
}

impl FromStr for WorkshopRole {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "viewer" => Ok(Self::Viewer),
            "artisan" => Ok(Self::Artisan),
            "accountant" => Ok(Self::Accountant),
            "studio_manager" => Ok(Self::StudioManager),
            "owner" => Ok(Self::Owner),
            _ => Err("unknown workshop role"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    TenantProvision,
    MembershipReconcile,
    EntitlementApply,
    InvoiceCapture,
    InventoryCaptureExtract,
    TenantReconcile,
    TenantLifecycle,
    EmailDelivery,
    ModuleEnable,
    ModuleRestrict,
    OdooReleaseAdopt,
    PrivacyRetention,
    PrivacyDataSubjectRequest,
    WebshopDomainReconcile,
    WebshopEmailDomainReconcile,
    WebshopOnboardingReconcile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationExecutionScope {
    Workshop(Uuid),
    Fleet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OperationScopeError {
    #[error("unknown operation kind")]
    UnknownKind,
    #[error("operation was leased from the wrong queue")]
    QueueMismatch,
    #[error("operation workshop scope does not match its kind")]
    WorkshopScopeMismatch,
}

impl OperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TenantProvision => "tenant.provision",
            Self::MembershipReconcile => "membership.reconcile",
            Self::EntitlementApply => "entitlement.apply",
            Self::InvoiceCapture => "invoice.capture",
            Self::InventoryCaptureExtract => "inventory.capture.extract",
            Self::TenantReconcile => "tenant.reconcile",
            Self::TenantLifecycle => "tenant.lifecycle",
            Self::EmailDelivery => "email.delivery",
            Self::ModuleEnable => "module.enable",
            Self::ModuleRestrict => "module.restrict",
            Self::OdooReleaseAdopt => "odoo.release.adopt",
            Self::PrivacyRetention => "privacy.retention",
            Self::PrivacyDataSubjectRequest => "privacy.data_subject_request",
            Self::WebshopDomainReconcile => "webshop-domain.reconcile",
            Self::WebshopEmailDomainReconcile => "webshop-email-domain.reconcile",
            Self::WebshopOnboardingReconcile => "webshop-onboarding.reconcile",
        }
    }

    pub fn queue(self) -> &'static str {
        match self {
            Self::TenantProvision => "tenant-provisioning",
            Self::MembershipReconcile => "membership-provisioning",
            Self::EntitlementApply => "membership-provisioning",
            Self::InvoiceCapture => "invoice-capture",
            Self::InventoryCaptureExtract => "inventory-capture",
            Self::TenantReconcile => "tenant-reconciliation",
            Self::TenantLifecycle => "tenant-lifecycle",
            Self::EmailDelivery => "email-delivery",
            Self::ModuleEnable => "tenant-reconciliation",
            Self::ModuleRestrict => "tenant-reconciliation",
            Self::OdooReleaseAdopt => "release-adoption",
            Self::PrivacyRetention | Self::PrivacyDataSubjectRequest => "privacy-operations",
            Self::WebshopDomainReconcile => "tenant-reconciliation",
            Self::WebshopEmailDomainReconcile => "tenant-reconciliation",
            Self::WebshopOnboardingReconcile => "tenant-reconciliation",
        }
    }

    pub const fn requires_workshop(self) -> bool {
        !matches!(
            self,
            Self::OdooReleaseAdopt | Self::PrivacyRetention | Self::PrivacyDataSubjectRequest
        )
    }

    pub fn execution_scope(
        self,
        leased_queue: &str,
        workshop_id: Option<Uuid>,
    ) -> Result<OperationExecutionScope, OperationScopeError> {
        if leased_queue != self.queue() {
            return Err(OperationScopeError::QueueMismatch);
        }
        match (self.requires_workshop(), workshop_id) {
            (true, Some(workshop_id)) if !workshop_id.is_nil() => {
                Ok(OperationExecutionScope::Workshop(workshop_id))
            }
            (false, None) => Ok(OperationExecutionScope::Fleet),
            _ => Err(OperationScopeError::WorkshopScopeMismatch),
        }
    }
}

impl FromStr for OperationKind {
    type Err = OperationScopeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "tenant.provision" => Ok(Self::TenantProvision),
            "membership.reconcile" => Ok(Self::MembershipReconcile),
            "entitlement.apply" => Ok(Self::EntitlementApply),
            "invoice.capture" => Ok(Self::InvoiceCapture),
            "inventory.capture.extract" => Ok(Self::InventoryCaptureExtract),
            "tenant.reconcile" => Ok(Self::TenantReconcile),
            "tenant.lifecycle" => Ok(Self::TenantLifecycle),
            "email.delivery" => Ok(Self::EmailDelivery),
            "module.enable" => Ok(Self::ModuleEnable),
            "module.restrict" => Ok(Self::ModuleRestrict),
            "odoo.release.adopt" => Ok(Self::OdooReleaseAdopt),
            "privacy.retention" => Ok(Self::PrivacyRetention),
            "privacy.data_subject_request" => Ok(Self::PrivacyDataSubjectRequest),
            "webshop-domain.reconcile" => Ok(Self::WebshopDomainReconcile),
            "webshop-email-domain.reconcile" => Ok(Self::WebshopEmailDomainReconcile),
            "webshop-onboarding.reconcile" => Ok(Self::WebshopOnboardingReconcile),
            _ => Err(OperationScopeError::UnknownKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Pending,
    InFlight,
    AwaitingReconciliation,
    Succeeded,
    DeadLetter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum IntegrationError {
    #[error("provider authentication failed")]
    Unauthorized,
    #[error("provider target not found")]
    NotFound,
    #[error("provider rejected the request")]
    Rejected,
    #[error("provider rate limited the request")]
    RateLimited { retry_after_seconds: Option<u64> },
    #[error("provider is unavailable")]
    Unavailable,
    #[error("provider outcome is unknown")]
    UnknownOutcome,
    #[error("provider contract drift")]
    ContractDrift,
    #[error("document exceeds the size limit")]
    TooLarge,
}

impl IntegrationError {
    pub fn failure_class(self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not_found",
            Self::Rejected => "rejected",
            Self::RateLimited { .. } => "rate_limited",
            Self::Unavailable => "upstream_unavailable",
            Self::UnknownOutcome => "unknown_outcome",
            Self::ContractDrift => "contract_drift",
            Self::TooLarge => "document_too_large",
        }
    }

    pub fn retryable(self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. } | Self::Unavailable | Self::UnknownOutcome
        )
    }

    pub fn retry_after_seconds(self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_seconds,
            } => retry_after_seconds,
            _ => None,
        }
    }
}

pub fn normalize_email(value: &str) -> Result<String, &'static str> {
    let normalized = value.trim().to_lowercase();
    if normalized.is_empty()
        || normalized.len() > 320
        || !normalized.contains('@')
        || normalized.chars().any(char::is_whitespace)
    {
        return Err("invalid email address");
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_is_never_an_invitation_role() {
        assert!(!WorkshopRole::Owner.can_invite());
        assert!(WorkshopRole::StudioManager.can_invite());
    }

    #[test]
    fn workshop_permissions_are_capability_oriented_and_fail_closed() {
        use WorkshopPermission::{
            ManageDatabase, ManageMembers, ManageModules, TransferOwnership, ViewWorkshop,
        };

        for role in [
            WorkshopRole::Viewer,
            WorkshopRole::Artisan,
            WorkshopRole::Accountant,
            WorkshopRole::StudioManager,
            WorkshopRole::Owner,
        ] {
            assert!(role.allows(ViewWorkshop));
        }
        assert!(WorkshopRole::StudioManager.allows(ManageMembers));
        assert!(WorkshopRole::StudioManager.allows(ManageModules));
        assert!(!WorkshopRole::StudioManager.allows(ManageDatabase));
        assert!(!WorkshopRole::StudioManager.allows(TransferOwnership));
        assert!(WorkshopRole::Owner.allows(ManageDatabase));
        assert!(WorkshopRole::Owner.allows(TransferOwnership));
        assert!(!WorkshopRole::Viewer.allows(ManageMembers));
        assert!(!WorkshopRole::Accountant.allows(ManageModules));
    }

    #[test]
    fn physical_database_reference_is_opaque() {
        let id = uuid::Uuid::parse_str("80f7149c-9215-48e8-88ce-8d1fe50bd656").unwrap();
        let reference = opaque_database_ref(id);
        assert_eq!(reference, "mb_80f7149c921548e888ce8d1fe50bd656");
        assert!(!reference.contains("workshop"));
    }

    #[test]
    fn each_operation_has_one_named_queue() {
        for kind in [
            OperationKind::TenantProvision,
            OperationKind::MembershipReconcile,
            OperationKind::EntitlementApply,
            OperationKind::InvoiceCapture,
            OperationKind::InventoryCaptureExtract,
            OperationKind::TenantReconcile,
            OperationKind::TenantLifecycle,
            OperationKind::EmailDelivery,
            OperationKind::ModuleEnable,
            OperationKind::ModuleRestrict,
            OperationKind::OdooReleaseAdopt,
            OperationKind::PrivacyRetention,
            OperationKind::PrivacyDataSubjectRequest,
            OperationKind::WebshopDomainReconcile,
            OperationKind::WebshopEmailDomainReconcile,
            OperationKind::WebshopOnboardingReconcile,
        ] {
            assert!(!kind.as_str().is_empty());
            assert!(!kind.queue().is_empty());
            assert_eq!(kind.as_str().parse::<OperationKind>(), Ok(kind));
        }
    }

    #[test]
    fn operation_execution_scope_is_closed_and_fail_closed() {
        let workshop = Uuid::new_v4();
        for kind in [
            OperationKind::TenantProvision,
            OperationKind::MembershipReconcile,
            OperationKind::EntitlementApply,
            OperationKind::InvoiceCapture,
            OperationKind::InventoryCaptureExtract,
            OperationKind::TenantReconcile,
            OperationKind::TenantLifecycle,
            OperationKind::EmailDelivery,
            OperationKind::ModuleEnable,
            OperationKind::ModuleRestrict,
            OperationKind::WebshopDomainReconcile,
            OperationKind::WebshopEmailDomainReconcile,
            OperationKind::WebshopOnboardingReconcile,
        ] {
            assert_eq!(
                kind.execution_scope(kind.queue(), Some(workshop)),
                Ok(OperationExecutionScope::Workshop(workshop))
            );
            assert_eq!(
                kind.execution_scope(kind.queue(), None),
                Err(OperationScopeError::WorkshopScopeMismatch)
            );
        }
        for kind in [
            OperationKind::OdooReleaseAdopt,
            OperationKind::PrivacyRetention,
            OperationKind::PrivacyDataSubjectRequest,
        ] {
            assert_eq!(
                kind.execution_scope(kind.queue(), None),
                Ok(OperationExecutionScope::Fleet)
            );
            assert_eq!(
                kind.execution_scope(kind.queue(), Some(workshop)),
                Err(OperationScopeError::WorkshopScopeMismatch)
            );
        }
        assert_eq!(
            OperationKind::MembershipReconcile
                .execution_scope("privacy-operations", Some(workshop)),
            Err(OperationScopeError::QueueMismatch)
        );
        assert_eq!(
            OperationKind::TenantLifecycle.execution_scope("tenant-lifecycle", Some(Uuid::nil())),
            Err(OperationScopeError::WorkshopScopeMismatch)
        );
        assert_eq!(
            "private.operation".parse::<OperationKind>(),
            Err(OperationScopeError::UnknownKind)
        );
    }

    #[test]
    fn email_normalization_is_deterministic() {
        assert_eq!(
            normalize_email("  ARTISAN@Example.Test ").unwrap(),
            "artisan@example.test"
        );
        assert!(normalize_email("not an address").is_err());
    }
}
