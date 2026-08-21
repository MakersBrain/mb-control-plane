use mb_control_plane::Config;
use mb_control_plane::persistence::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let queue = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: control-worker <queue>"))?;
    let service_name = match queue.as_str() {
        "tenant-provisioning" => "mb-worker-provisioning",
        "membership-provisioning" => "mb-worker-membership",
        "invoice-capture" => "mb-worker-invoice",
        "inventory-capture" => "mb-worker-inventory",
        "email-delivery" => "mb-worker-email",
        "tenant-reconciliation" => "mb-worker-reconciliation",
        "tenant-lifecycle" => "mb-worker-lifecycle",
        "release-adoption" => "mb-worker-release",
        "privacy-operations" => "mb-worker-privacy",
        _ => "mb-worker-invalid",
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
    mb_control_plane::startup_config::validate_process(process)?;
    let _telemetry = mb_control_plane::telemetry::init(service_name)?;
    let database_url = Config::database_url()?;
    let store = Store::connect(&database_url).await?;
    mb_control_plane::worker::run(store, &queue).await
}
