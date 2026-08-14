use makersbrain_control_plane::Config;
use makersbrain_control_plane::persistence::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let queue = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: control-worker <queue>"))?;
    let service_name = match queue.as_str() {
        "tenant-provisioning" => "makersbrain-worker-provisioning",
        "membership-provisioning" => "makersbrain-worker-membership",
        "invoice-capture" => "makersbrain-worker-invoice",
        "inventory-capture" => "makersbrain-worker-inventory",
        "email-delivery" => "makersbrain-worker-email",
        "tenant-reconciliation" => "makersbrain-worker-reconciliation",
        "tenant-lifecycle" => "makersbrain-worker-lifecycle",
        "release-adoption" => "makersbrain-worker-release",
        "privacy-operations" => "makersbrain-worker-privacy",
        _ => "makersbrain-worker-invalid",
    };
    let process = match queue.as_str() {
        "tenant-provisioning" => "provisioning_worker",
        "membership-provisioning" => "membership_worker",
        "invoice-capture" => "invoice_worker",
        "inventory-capture" => "inventory_worker",
        "email-delivery" => "email_worker",
        "tenant-reconciliation" => "reconciliation_worker",
        "tenant-lifecycle" => "lifecycle_worker",
        "release-adoption" => "release_worker",
        "privacy-operations" => "privacy_worker",
        _ => anyhow::bail!("unknown worker queue {queue}"),
    };
    makersbrain_control_plane::startup_config::validate_process(process)?;
    let _telemetry = makersbrain_control_plane::telemetry::init(service_name)?;
    let database_url = Config::database_url()?;
    let store = Store::connect(&database_url).await?;
    makersbrain_control_plane::worker::run(store, &queue).await
}
