use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
pub struct ModuleBundle {
    pub key: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub odoo_modules: &'static [&'static str],
    pub dependencies: &'static [&'static str],
    pub service: Option<&'static str>,
    pub minimum_release: &'static str,
}

pub const REGISTRY_VERSION: u32 = 2;

#[derive(Debug, Deserialize)]
pub(crate) struct EmbeddedCapabilityRegistry {
    pub version: u32,
    pub minimum_application_release: String,
    pub capabilities: Vec<EmbeddedCapability>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EmbeddedCapability {
    pub key: String,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub odoo_modules: Vec<String>,
    pub service: Option<String>,
}

const EMBEDDED_REGISTRY: &[u8] = include_bytes!("../deploy/capability-registry-v2.json");

pub(crate) fn embedded_registry() -> anyhow::Result<EmbeddedCapabilityRegistry> {
    serde_json::from_slice(EMBEDDED_REGISTRY)
        .map_err(|error| anyhow::anyhow!("embedded capability registry is invalid: {error}"))
}

pub(crate) fn embedded_registry_digest() -> String {
    format!("sha256:{:x}", Sha256::digest(EMBEDDED_REGISTRY))
}

pub const CATALOG: &[ModuleBundle] = &[
    ModuleBundle {
        key: "ceramics-production",
        name: "Ceramics production",
        description: "Run throwing, finishing, bisque, glazing and quality workflows with lot traceability.",
        odoo_modules: &["mb_ceramics_workflow"],
        dependencies: &["firings"],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "catalogue",
        name: "Ceramics catalogue",
        description: "Import curated materials and supplier catalogue entries.",
        odoo_modules: &["mb_catalogue_sync"],
        dependencies: &[],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "firings",
        name: "Kilns and firings",
        description: "Plan firings, firing curves, kiln work centres, and maintenance.",
        odoo_modules: &["mb_ceramics_firing"],
        dependencies: &[],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "kiln-connectivity",
        name: "Kiln connectivity",
        description: "Connect supported kiln controllers and synchronize firing data.",
        odoo_modules: &["mb_kiln_bridge"],
        dependencies: &["firings"],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "labels",
        name: "Labels and POS QR",
        description: "Design labels and print product and POS QR labels.",
        odoo_modules: &["mb_label", "mb_label_pos"],
        dependencies: &[],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "depot",
        name: "Depot sales",
        description: "Manage consignment stock, commissions, and depot statements.",
        odoo_modules: &["mb_depot"],
        dependencies: &[],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "sumup",
        name: "SumUp payments",
        description: "Use SumUp for online invoices, payment links, and POS checkout.",
        odoo_modules: &[
            "mb_payment_sumup",
            "mb_account_payment_sumup",
            "mb_pos_sumup",
        ],
        dependencies: &[],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "webshop",
        name: "Artisan webshop",
        description: "Publish a craft storefront with native theme editing, stock-aware checkout, delivery and collection.",
        odoo_modules: &["mb_webshop"],
        dependencies: &[],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "shop-catalogue-import",
        name: "Shop catalogue import",
        description: "Review scraper catalogue artifacts before importing products, prices, stock and images.",
        odoo_modules: &["mb_shop_import"],
        dependencies: &[],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "shipping-boxtal",
        name: "Boxtal shipping",
        description: "Buy Boxtal labels, offer parcel-point checkout and receive signed tracking updates.",
        odoo_modules: &["mb_webshop_carrier_base", "mb_webshop_carrier_boxtal"],
        dependencies: &["webshop"],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "inventory-capture",
        name: "Product photo inventory capture",
        description: "Identify receipt products and supplier lots from sanitized label photographs.",
        odoo_modules: &["mb_inventory_capture"],
        dependencies: &[],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "azure-label-extraction",
        name: "Azure label extraction",
        description: "Use Azure Document Intelligence Read for product-label OCR.",
        odoo_modules: &[],
        dependencies: &["inventory-capture"],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "inventory-ai-fallback",
        name: "Inventory label AI fallback",
        description: "Suggest product and lot candidates when deterministic label extraction is inconclusive.",
        odoo_modules: &[],
        dependencies: &["inventory-capture"],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "documents",
        name: "Documents",
        description: "Provision a private Paperless-ngx archive for this workshop.",
        odoo_modules: &[],
        dependencies: &[],
        service: Some("paperless"),
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "invoice-capture",
        name: "Invoice capture",
        description: "Import structured supplier invoices from the document archive into Odoo.",
        odoo_modules: &["mb_invoice_capture"],
        dependencies: &["documents"],
        service: None,
        minimum_release: "0.1.0",
    },
    ModuleBundle {
        key: "azure-invoice-extraction",
        name: "Azure invoice extraction",
        description: "Extract scanned and unstructured supplier invoices with Azure Document Intelligence.",
        odoo_modules: &[],
        dependencies: &["invoice-capture"],
        service: None,
        minimum_release: "0.1.0",
    },
];

pub fn bundle(key: &str) -> Option<&'static ModuleBundle> {
    CATALOG.iter().find(|bundle| bundle.key == key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_keys_and_odoo_modules_are_unique() {
        let mut keys = std::collections::HashSet::new();
        let mut modules = std::collections::HashSet::new();
        for bundle in CATALOG {
            assert!(keys.insert(bundle.key));
            for module in bundle.odoo_modules {
                assert!(modules.insert(*module));
            }
            for dependency in bundle.dependencies {
                assert_ne!(*dependency, bundle.key);
            }
        }
        for bundle in CATALOG {
            assert!(bundle.dependencies.iter().all(|key| keys.contains(key)));
        }
        assert_eq!(REGISTRY_VERSION, 2);
        let embedded = embedded_registry().unwrap();
        assert_eq!(embedded.version, REGISTRY_VERSION);
        assert_eq!(embedded.capabilities.len(), CATALOG.len());
        assert_eq!(
            bundle("ceramics-production").unwrap().odoo_modules,
            &["mb_ceramics_workflow"]
        );
        assert_eq!(
            bundle("kiln-connectivity").unwrap().dependencies,
            &["firings"]
        );
        assert_eq!(bundle("webshop").unwrap().odoo_modules, &["mb_webshop"]);
        assert_eq!(
            bundle("shop-catalogue-import").unwrap().odoo_modules,
            &["mb_shop_import"]
        );
        assert_eq!(
            bundle("shipping-boxtal").unwrap().odoo_modules,
            &["mb_webshop_carrier_base", "mb_webshop_carrier_boxtal"]
        );
        assert_eq!(
            bundle("shipping-boxtal").unwrap().dependencies,
            &["webshop"]
        );
    }
}
