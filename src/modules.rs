#[derive(Debug, Clone, Copy)]
pub struct ModuleBundle {
    pub key: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub odoo_modules: &'static [&'static str],
    pub dependencies: &'static [&'static str],
    pub service: Option<&'static str>,
}

pub const CATALOG: &[ModuleBundle] = &[
    ModuleBundle {
        key: "catalogue",
        name: "Ceramics catalogue",
        description: "Import curated materials and supplier catalogue entries.",
        odoo_modules: &["mb_catalogue_sync"],
        dependencies: &[],
        service: None,
    },
    ModuleBundle {
        key: "firings",
        name: "Kilns and firings",
        description: "Plan firings, firing curves, kiln work centres, and maintenance.",
        odoo_modules: &["mb_ceramics_firing"],
        dependencies: &[],
        service: None,
    },
    ModuleBundle {
        key: "kiln-connectivity",
        name: "Kiln connectivity",
        description: "Connect supported kiln controllers and synchronize firing data.",
        odoo_modules: &["mb_kiln_bridge"],
        dependencies: &[],
        service: None,
    },
    ModuleBundle {
        key: "labels",
        name: "Labels and POS QR",
        description: "Design labels and print product and POS QR labels.",
        odoo_modules: &["mb_label", "mb_label_pos"],
        dependencies: &[],
        service: None,
    },
    ModuleBundle {
        key: "depot",
        name: "Depot sales",
        description: "Manage consignment stock, commissions, and depot statements.",
        odoo_modules: &["mb_depot"],
        dependencies: &[],
        service: None,
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
    },
    ModuleBundle {
        key: "documents",
        name: "Documents",
        description: "Provision a private Paperless-ngx archive for this workshop.",
        odoo_modules: &[],
        dependencies: &[],
        service: Some("paperless"),
    },
    ModuleBundle {
        key: "invoice-capture",
        name: "Invoice capture",
        description: "Import structured supplier invoices from the document archive into Odoo.",
        odoo_modules: &["mb_invoice_capture"],
        dependencies: &["documents"],
        service: None,
    },
    ModuleBundle {
        key: "azure-invoice-extraction",
        name: "Azure invoice extraction",
        description: "Extract scanned and unstructured supplier invoices with Azure Document Intelligence.",
        odoo_modules: &[],
        dependencies: &["invoice-capture"],
        service: None,
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
    }
}
