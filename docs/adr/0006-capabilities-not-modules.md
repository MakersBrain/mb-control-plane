# ADR 0006: Product capabilities are not Odoo module names

Status: accepted

Users select stable product capabilities such as documents, invoicing or kiln
workflows. A versioned registry maps each capability to Odoo modules, services,
dependencies, minimum application release and entitlement policy.

The control plane stores desired, installing, enabled, restricted and failed
states. It activates only entitled capabilities whose required release is
available, and verifies observed module/service evidence. Restriction does not
automatically uninstall modules or destroy tenant data.
