use serde::{Deserialize, Serialize};
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkshopRole {
    Viewer,
    Artisan,
    Accountant,
    StudioManager,
    Owner,
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
        ] {
            assert!(!kind.as_str().is_empty());
            assert!(!kind.queue().is_empty());
        }
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
