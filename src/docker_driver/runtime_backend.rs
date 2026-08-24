use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::unix::fs::symlink;
use std::process::Stdio;

use bytes::Bytes;

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RuntimeState {
    Running,
    Stopped,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum RuntimeHealth {
    Healthy,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct RuntimeObservation {
    pub resource_key: String,
    pub desired_digest: String,
    pub observed_digest: Option<String>,
    pub image_digest: Option<String>,
    pub state: RuntimeState,
    pub health: RuntimeHealth,
    pub runtime_object_id: Option<String>,
}

#[derive(Clone, Debug)]
pub(super) struct PaperlessDesired {
    pub workshop: Uuid,
    pub container_name: String,
    pub image: String,
    pub config_digest: String,
    pub environment: Vec<(String, String)>,
    pub secret_directory: PathBuf,
    pub volumes: Vec<(String, String)>,
    pub network: String,
}

#[derive(Clone, Debug)]
pub(super) struct OdooSlotDesired {
    pub slot: String,
    pub container_name: String,
    pub image: String,
    pub config_digest: String,
    pub environment: Vec<(String, String)>,
    pub secret_directory: PathBuf,
    pub client_secret_directory: PathBuf,
    pub postgres_ca: Option<PathBuf>,
    pub extension_volume: String,
    pub data_volume: String,
    pub network: String,
    pub boot_selected: bool,
}

#[derive(Clone)]
pub(super) enum RuntimeBackend {
    Docker,
    Quadlet(QuadletBackend),
}

#[derive(Clone)]
pub(super) struct QuadletBackend {
    root: PathBuf,
    runtime_dir: PathBuf,
    grant_root: PathBuf,
    allow_raw_migration: bool,
}

impl RuntimeBackend {
    pub(super) fn from_config(config: &DockerDriverConfig) -> anyhow::Result<Self> {
        match config.backend {
            DriverBackendKind::Docker => Ok(Self::Docker),
            DriverBackendKind::Quadlet => Ok(Self::Quadlet(QuadletBackend {
                root: config
                    .quadlet_root
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("DRIVER_QUADLET_ROOT is required"))?,
                runtime_dir: config
                    .systemd_runtime_dir
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("DRIVER_SYSTEMD_RUNTIME_DIR is required"))?,
                grant_root: config
                    .image_grant_root
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("DRIVER_IMAGE_GRANT_ROOT is required"))?,
                allow_raw_migration: config.allow_raw_podman_migration,
            })),
        }
    }
}

impl QuadletBackend {
    pub(super) async fn create_archive_container(
        &self,
        name: &str,
        body: &Value,
    ) -> Result<(), DriverError> {
        validate_name(name)?;
        let image = body
            .get("Image")
            .and_then(Value::as_str)
            .ok_or_else(|| DriverError::internal("archive container image is required"))?;
        validate_digest_image(image)?;
        self.assert_image_admitted(image)?;
        let kind = body
            .pointer("/Labels/mb.kind")
            .and_then(Value::as_str)
            .unwrap_or("odoo-extension-staging");
        if !matches!(kind, "odoo-extension-source" | "odoo-extension-staging") {
            return Err(DriverError::internal("unapproved archive container kind"));
        }
        self.assert_image_role(
            image,
            if kind == "odoo-extension-source" {
                &["odoo_extension"]
            } else {
                &["control"]
            },
        )?;
        let mut args = vec![
            "create".to_owned(),
            "--name".to_owned(),
            name.to_owned(),
            "--pull=never".to_owned(),
            "--network=none".to_owned(),
            "--read-only".to_owned(),
            "--cap-drop=all".to_owned(),
            "--security-opt=no-new-privileges".to_owned(),
            "--label".to_owned(),
            format!("mb.kind={kind}"),
        ];
        if let Some(host) = body.get("HostConfig").and_then(Value::as_object) {
            for bind in host
                .get("Binds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let bind = bind
                    .as_str()
                    .ok_or_else(|| DriverError::internal("invalid archive container bind"))?;
                validate_volume_value(bind)?;
                args.extend(["--volume".into(), bind.into()]);
            }
        }
        if let Some(entrypoint) = body
            .get("Entrypoint")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_str)
        {
            validate_cli_value(entrypoint)?;
            args.extend(["--entrypoint".into(), entrypoint.into()]);
        }
        args.push(image.into());
        for argument in body
            .get("Cmd")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let argument = argument
                .as_str()
                .ok_or_else(|| DriverError::internal("invalid archive container command"))?;
            validate_cli_value(argument)?;
            args.push(argument.into());
        }
        self.command("podman", args, None).await?;
        Ok(())
    }

    pub(super) async fn get_archive(
        &self,
        container: &str,
        path: &str,
        maximum: usize,
    ) -> Result<Bytes, DriverError> {
        validate_name(container)?;
        validate_absolute_directory(Path::new(path))?;
        let output = self
            .command_bytes(
                "podman",
                ["cp", &format!("{container}:{path}"), "-"],
                None,
                maximum,
            )
            .await?;
        Ok(Bytes::from(output))
    }

    pub(super) async fn put_archive(
        &self,
        container: &str,
        path: &str,
        archive: Bytes,
    ) -> Result<(), DriverError> {
        validate_name(container)?;
        validate_absolute_directory(Path::new(path))?;
        self.command_bytes(
            "podman",
            ["cp", "-", &format!("{container}:{path}")],
            Some(archive),
            2 * 1024 * 1024,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn container_exists(&self, name: &str) -> Result<bool, DriverError> {
        validate_name(name)?;
        self.command_success("podman", ["container", "exists", name])
            .await
    }

    pub(super) async fn delete_container(&self, name: &str) -> Result<(), DriverError> {
        validate_name(name)?;
        if self.job_active(name).await? {
            return Err(DriverError::internal(
                "the deterministic runtime job is still active",
            ));
        }
        if self.container_exists(name).await? {
            self.command("podman", ["rm", "--force", name], None)
                .await?;
        }
        Ok(())
    }

    pub(super) async fn inspect_container(&self, name: &str) -> Result<Value, DriverError> {
        validate_name(name)?;
        let output = self.command("podman", ["inspect", name], None).await?;
        let mut values: Vec<Value> =
            serde_json::from_str(&output).map_err(DriverError::internal)?;
        values
            .pop()
            .ok_or_else(|| DriverError::internal("runtime container inspection is empty"))
    }

    pub(super) async fn start_container(&self, name: &str) -> Result<(), DriverError> {
        let unit = self.unit_for_container(name)?;
        self.set_state(&unit, RuntimeState::Running).await
    }

    pub(super) async fn stop_container(&self, name: &str) -> Result<(), DriverError> {
        let unit = self.unit_for_container(name)?;
        self.set_state(&unit, RuntimeState::Stopped).await
    }

    pub(super) async fn remove_persistent_container(&self, name: &str) -> Result<(), DriverError> {
        let (unit, path) = self.unit_path_for_container(name)?;
        self.set_state(&unit, RuntimeState::Stopped).await?;
        std::fs::remove_file(path).map_err(DriverError::internal)?;
        self.systemctl(["daemon-reload"]).await
    }

    pub(super) async fn set_container_boot_selected(
        &self,
        container: &str,
        selected: bool,
    ) -> Result<(), DriverError> {
        let (unit, path) = self.unit_path_for_container(container)?;
        let category = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|value| value.to_str())
            .ok_or_else(|| DriverError::internal("selected Quadlet category is invalid"))?;
        let mut source = std::fs::read_to_string(&path).map_err(DriverError::internal)?;
        let install = "\n[Install]\nWantedBy=default.target\n";
        source = source.replace(install, "");
        if selected {
            source.push_str(install);
        }
        let image = source
            .lines()
            .find_map(|line| line.strip_prefix("Image="))
            .ok_or_else(|| DriverError::internal("selected Quadlet image is missing"))?
            .to_owned();
        let digest = source
            .lines()
            .find_map(|line| line.strip_prefix("Label=mb.config-digest="))
            .ok_or_else(|| DriverError::internal("selected Quadlet digest is missing"))?
            .to_owned();
        self.install_and_start(
            &format!("{category}/{unit}"),
            category,
            &unit,
            &source,
            &image,
            &digest,
            selected,
        )
        .await?;
        if !selected {
            self.set_state(&unit, RuntimeState::Stopped).await?;
        }
        Ok(())
    }

    pub(super) async fn container_boot_selected(
        &self,
        container: &str,
    ) -> Result<bool, DriverError> {
        let unit = self.unit_for_container(container)?;
        self.command_success("systemctl", ["--user", "is-enabled", &unit])
            .await
    }

    fn unit_for_container(&self, name: &str) -> Result<String, DriverError> {
        self.unit_path_for_container(name).map(|(unit, _)| unit)
    }

    fn unit_path_for_container(&self, name: &str) -> Result<(String, PathBuf), DriverError> {
        validate_name(name)?;
        for category in ["paperless", "odoo-slots"] {
            let directory = self.root.join(category);
            if !directory.exists() {
                continue;
            }
            for entry in std::fs::read_dir(directory).map_err(DriverError::internal)? {
                let entry = entry.map_err(DriverError::internal)?;
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("container") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).map_err(DriverError::internal)?;
                if unit_container_name(&source)? == name {
                    let unit = path
                        .file_stem()
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| DriverError::internal("invalid selected Quadlet name"))?;
                    validate_name(unit)?;
                    return Ok((unit.into(), path));
                }
            }
        }
        Err(DriverError::internal(
            "container is not owned by a selected persistent Quadlet",
        ))
    }

    pub(super) async fn image_inspect(&self, image: &str) -> Result<Value, DriverError> {
        validate_digest_image(image)?;
        self.assert_image_admitted(image)?;
        let output = self
            .command("podman", ["image", "inspect", image], None)
            .await?;
        let mut values: Vec<Value> =
            serde_json::from_str(&output).map_err(DriverError::internal)?;
        let mut inspect = values
            .pop()
            .ok_or_else(|| DriverError::internal("admitted image is not present"))?;
        if inspect.get("Descriptor").is_none()
            && let Some(digest) = inspect.get("Digest").cloned()
        {
            inspect["Descriptor"] = json!({"digest": digest});
        }
        Ok(inspect)
    }

    pub(super) async fn assert_image_present(&self, image: &str) -> Result<(), DriverError> {
        self.image_inspect(image).await.map(|_| ())
    }

    pub(super) async fn volume_exists(&self, name: &str) -> Result<bool, DriverError> {
        validate_name(name)?;
        self.command_success("podman", ["volume", "exists", name])
            .await
    }

    pub(super) async fn create_extension_volume(
        &self,
        name: &str,
        manifest: &str,
        payload: &str,
    ) -> Result<(), DriverError> {
        validate_name(name)?;
        validate_digest(manifest)?;
        validate_digest(payload)?;
        self.command(
            "podman",
            [
                "volume",
                "create",
                "--label",
                "mb.kind=odoo-extension",
                "--label",
                &format!("mb.extension-manifest={manifest}"),
                "--label",
                &format!("mb.payload={payload}"),
                name,
            ],
            None,
        )
        .await?;
        Ok(())
    }

    pub(super) async fn delete_volume(&self, name: &str) -> Result<bool, DriverError> {
        validate_name(name)?;
        if !self.volume_exists(name).await? {
            return Ok(false);
        }
        self.command("podman", ["volume", "rm", name], None).await?;
        Ok(true)
    }

    pub(super) async fn ensure_volume(&self, name: &str) -> Result<(), DriverError> {
        validate_name(name)?;
        let exists = self
            .command("podman", ["volume", "exists", name], None)
            .await;
        if exists.is_err() {
            self.command(
                "podman",
                [
                    "volume",
                    "create",
                    "--label",
                    "mb.kind=managed-volume",
                    name,
                ],
                None,
            )
            .await?;
        }
        Ok(())
    }

    pub(super) async fn run_job(&self, container: &str, body: &Value) -> Result<(), DriverError> {
        validate_name(container)?;
        let object = body
            .as_object()
            .ok_or_else(|| DriverError::internal("runtime job must be an object"))?;
        let image = object
            .get("Image")
            .and_then(Value::as_str)
            .ok_or_else(|| DriverError::internal("runtime job image is required"))?;
        validate_digest_image(image)?;
        self.assert_image_admitted(image)?;
        let labels = object.get("Labels").and_then(Value::as_object);
        let kind = labels
            .and_then(|labels| labels.get("mb.kind"))
            .and_then(Value::as_str)
            .unwrap_or("odoo-extension-verifier");
        if !matches!(
            kind,
            "postgres-lifecycle-job"
                | "odoo-init"
                | "odoo-break-glass"
                | "odoo-release-upgrade"
                | "odoo-extension-helper"
                | "odoo-extension-verifier"
                | "s3-backup-presign-job"
                | "encrypted-backup-job"
                | "encrypted-backup-manifest-job"
                | "portable-backup-archive-job"
                | "s3-backup-upload-job"
                | "s3-restore-download-job"
                | "s3-restore-verify-job"
                | "encrypted-restore-job"
                | "restore-preflight-job"
                | "paperless-recovery-job"
        ) {
            return Err(DriverError::internal("unapproved runtime job kind"));
        }
        let image_roles: &[&str] = match kind {
            "postgres-lifecycle-job" | "paperless-recovery-job" => &["postgres"],
            "odoo-init" | "odoo-break-glass" | "odoo-release-upgrade" => &["odoo"],
            "odoo-extension-helper" | "odoo-extension-verifier" => &["control"],
            _ => &["backup"],
        };
        self.assert_image_role(image, image_roles)?;

        let mut podman = vec![
            "run".to_owned(),
            "--rm".to_owned(),
            "--name".to_owned(),
            container.to_owned(),
            "--pull=never".to_owned(),
            "--security-opt=no-new-privileges".to_owned(),
            "--cap-drop=all".to_owned(),
            "--group-add=keep-groups".to_owned(),
            "--label".to_owned(),
            format!("mb.kind={kind}"),
        ];
        if let Some(labels) = labels {
            for (key, value) in labels {
                if key == "mb.kind" {
                    continue;
                }
                validate_runtime_label(key, value)?;
                podman.extend([
                    "--label".into(),
                    format!("{key}={}", value.as_str().expect("validated label")),
                ]);
            }
        }
        if object.get("NetworkDisabled").and_then(Value::as_bool) == Some(true) {
            podman.push("--network=none".into());
        }
        if let Some(user) = object.get("User").and_then(Value::as_str) {
            validate_cli_value(user)?;
            podman.extend(["--user".into(), user.into()]);
        }
        if let Some(entrypoint) = object.get("Entrypoint").and_then(Value::as_array) {
            if entrypoint.len() != 1 {
                return Err(DriverError::internal(
                    "job entrypoint must contain one value",
                ));
            }
            let entrypoint = entrypoint[0]
                .as_str()
                .ok_or_else(|| DriverError::internal("invalid job entrypoint"))?;
            validate_cli_value(entrypoint)?;
            podman.extend(["--entrypoint".into(), entrypoint.into()]);
        }
        for environment in object
            .get("Env")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let environment = environment
                .as_str()
                .ok_or_else(|| DriverError::internal("invalid job environment"))?;
            let (key, value) = environment
                .split_once('=')
                .ok_or_else(|| DriverError::internal("invalid job environment"))?;
            validate_job_environment(key, value)?;
            podman.extend(["--env".into(), environment.into()]);
        }
        if let Some(host) = object.get("HostConfig").and_then(Value::as_object) {
            if host.get("ReadonlyRootfs").and_then(Value::as_bool) == Some(true) {
                podman.push("--read-only".into());
            }
            if let Some(network) = host.get("NetworkMode").and_then(Value::as_str) {
                validate_name_or_none(network)?;
                podman.extend(["--network".into(), network.into()]);
            }
            if let Some(limit) = host.get("PidsLimit").and_then(Value::as_u64) {
                podman.extend(["--pids-limit".into(), limit.to_string()]);
            }
            if let Some(limit) = host.get("Memory").and_then(Value::as_u64) {
                podman.extend(["--memory".into(), limit.to_string()]);
            }
            for bind in host
                .get("Binds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let bind = bind
                    .as_str()
                    .ok_or_else(|| DriverError::internal("invalid job bind"))?;
                validate_volume_value(bind)?;
                podman.extend(["--volume".into(), bind.into()]);
            }
            for mount in host
                .get("Mounts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let mount = mount
                    .as_object()
                    .ok_or_else(|| DriverError::internal("invalid job mount"))?;
                if mount.get("Type").and_then(Value::as_str) != Some("bind") {
                    return Err(DriverError::internal("only bind job mounts are allowed"));
                }
                let source = mount
                    .get("Source")
                    .and_then(Value::as_str)
                    .ok_or_else(|| DriverError::internal("job mount source is required"))?;
                let target = mount
                    .get("Target")
                    .and_then(Value::as_str)
                    .ok_or_else(|| DriverError::internal("job mount target is required"))?;
                validate_absolute_directory(Path::new(source))?;
                validate_absolute_directory(Path::new(target))?;
                let suffix = if mount.get("ReadOnly").and_then(Value::as_bool) == Some(true) {
                    ":ro"
                } else {
                    ""
                };
                podman.extend(["--volume".into(), format!("{source}:{target}{suffix}")]);
            }
            if let Some(tmpfs) = host.get("Tmpfs").and_then(Value::as_object) {
                for (path, options) in tmpfs {
                    validate_absolute_directory(Path::new(path))?;
                    let options = options
                        .as_str()
                        .ok_or_else(|| DriverError::internal("invalid tmpfs options"))?;
                    validate_cli_value(options)?;
                    podman.extend(["--tmpfs".into(), format!("{path}:{options}")]);
                }
            }
        }
        podman.push(image.into());
        for argument in object
            .get("Cmd")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let argument = argument
                .as_str()
                .ok_or_else(|| DriverError::internal("invalid job command"))?;
            validate_cli_value(argument)?;
            podman.push(argument.into());
        }
        if self.job_active(container).await? {
            return Err(DriverError::internal(
                "the deterministic runtime job is already active",
            ));
        }
        let unit = format!("mb-job-{container}");
        let mut args = vec![
            "--user".into(),
            "--wait".into(),
            "--collect".into(),
            "--quiet".into(),
            "--unit".into(),
            unit.clone(),
            "--property=NoNewPrivileges=yes".into(),
            "--property=PrivateTmp=yes".into(),
            "podman".into(),
        ];
        args.extend(podman);
        let result = self
            .command_with_timeout("systemd-run", args, None, Duration::from_secs(7200))
            .await;
        if result.is_err() {
            let service = format!("{unit}.service");
            let _ = self.systemctl(["stop", &service]).await;
            for _ in 0..30 {
                if !self.job_active(container).await.unwrap_or(true) {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            if self.job_active(container).await.unwrap_or(true) {
                return Err(DriverError::internal(
                    "runtime job could not be made terminal before secret cleanup",
                ));
            }
            let _ = self.delete_container(container).await;
        }
        result.map(|_| ())
    }

    pub(super) fn workspace_resource_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, DriverError> {
        if !(1..=docker_client::WORKSPACE_RUNTIME_PAGE_LIMIT).contains(&limit) {
            return Err(DriverError::internal(
                "workspace runtime page request is invalid",
            ));
        }
        if let Some(after) = after {
            validate_name(after)?;
        }
        let mut resources = BTreeSet::new();
        for category in ["paperless", "odoo-slots"] {
            let directory = self.root.join(category);
            if !directory.exists() {
                continue;
            }
            if std::fs::symlink_metadata(&directory)
                .map_err(DriverError::internal)?
                .file_type()
                .is_symlink()
                || !directory.is_dir()
            {
                return Err(DriverError::internal(
                    "workspace runtime category is not a safe directory",
                ));
            }
            for entry in std::fs::read_dir(&directory).map_err(DriverError::internal)? {
                let entry = entry.map_err(DriverError::internal)?;
                if let Some(unit) = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.strip_suffix(".container"))
                {
                    validate_name(unit)?;
                    let other_category = if category == "paperless" {
                        "odoo-slots"
                    } else {
                        "paperless"
                    };
                    if std::fs::symlink_metadata(
                        self.root.join(other_category).join(entry.file_name()),
                    )
                    .is_ok()
                    {
                        return Err(DriverError::internal(
                            "workspace runtime identity is ambiguous",
                        ));
                    }
                    if after.is_none_or(|cursor| unit > cursor) {
                        resources.insert(unit.to_owned());
                        if resources.len() > limit {
                            resources.pop_last();
                        }
                    }
                }
            }
        }
        Ok(resources.into_iter().collect())
    }

    pub(super) fn workspace_resource_exists(&self, unit: &str) -> Result<bool, DriverError> {
        validate_name(unit)?;
        let category = if unit.starts_with("mb-paperless-") {
            "paperless"
        } else if unit.starts_with("mb-odoo-") {
            "odoo-slots"
        } else {
            return Err(DriverError::internal(
                "workspace runtime identity has an invalid category",
            ));
        };
        let directory = self.root.join(category);
        if !directory.exists() {
            return Ok(false);
        }
        if std::fs::symlink_metadata(&directory)
            .map_err(DriverError::internal)?
            .file_type()
            .is_symlink()
            || !directory.is_dir()
        {
            return Err(DriverError::internal(
                "workspace runtime category is not a safe directory",
            ));
        }
        match std::fs::symlink_metadata(directory.join(format!("{unit}.container"))) {
            Ok(metadata) if metadata.file_type().is_symlink() => Ok(true),
            Ok(_) => Err(DriverError::internal(
                "selected workspace runtime is not a symlink",
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(DriverError::internal(error)),
        }
    }

    pub(super) fn workspace_resources(&self) -> Result<Vec<String>, DriverError> {
        let mut resources = Vec::new();
        let mut after = None;
        loop {
            let page = self.workspace_resource_page(
                after.as_deref(),
                docker_client::WORKSPACE_RUNTIME_PAGE_LIMIT,
            )?;
            let full = page.len() == docker_client::WORKSPACE_RUNTIME_PAGE_LIMIT;
            if full && page.last() == after.as_ref() {
                return Err(DriverError::internal(
                    "workspace runtime cursor did not advance",
                ));
            }
            after = page.last().cloned();
            resources.extend(page);
            if !full {
                return Ok(resources);
            }
        }
    }

    pub(super) async fn reconcile_persistent_unit(
        &self,
        category: &str,
        unit: &str,
        expected_image: Option<&str>,
        expected_config_digest: &str,
        desired_state: RuntimeState,
    ) -> Result<RuntimeObservation, DriverError> {
        if !matches!(category, "paperless" | "odoo-slots") {
            return Err(DriverError::internal("invalid Quadlet resource category"));
        }
        validate_name(unit)?;
        validate_digest(expected_config_digest)?;
        let source =
            std::fs::read_to_string(self.root.join(category).join(format!("{unit}.container")))
                .map_err(DriverError::internal)?;
        if source
            .lines()
            .find_map(|line| line.strip_prefix("Label=mb.config-digest="))
            != Some(expected_config_digest)
        {
            return Err(DriverError::internal(
                "Quadlet configuration identity drifted",
            ));
        }
        let observed_image = source.lines().find_map(|line| line.strip_prefix("Image="));
        if expected_image.is_some_and(|expected| observed_image != Some(expected)) {
            return Err(DriverError::internal("Quadlet image identity drifted"));
        }
        self.set_state(unit, desired_state.clone()).await?;
        let health = if desired_state == RuntimeState::Running && category == "paperless" {
            let container = unit_container_name(&source)?;
            let mut healthy = false;
            for _ in 0..3 {
                let status = self
                    .command(
                        "podman",
                        ["inspect", "--format", "{{.State.Health.Status}}", container],
                        None,
                    )
                    .await?;
                if status.trim() == "healthy" {
                    healthy = true;
                    break;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            if !healthy {
                return Err(DriverError::internal(
                    "persistent Paperless unit is not healthy",
                ));
            }
            RuntimeHealth::Healthy
        } else {
            RuntimeHealth::Unknown
        };
        Ok(RuntimeObservation {
            resource_key: format!("{category}/{unit}"),
            desired_digest: expected_config_digest.into(),
            observed_digest: Some(format!("sha256:{:x}", Sha256::digest(source.as_bytes()))),
            image_digest: observed_image.map(str::to_owned),
            state: desired_state,
            health,
            runtime_object_id: Some(unit.into()),
        })
    }

    pub(super) async fn reload_gateway(
        &self,
        container: &str,
        expected_digest: &str,
    ) -> Result<RuntimeObservation, DriverError> {
        validate_name(container)?;
        validate_digest(expected_digest)?;
        self.command("podman", ["exec", container, "nginx", "-t"], None)
            .await?;
        self.command("podman", ["kill", "--signal", "HUP", container], None)
            .await?;
        Ok(RuntimeObservation {
            resource_key: "service/tenant-gateway".into(),
            desired_digest: expected_digest.into(),
            observed_digest: Some(expected_digest.into()),
            image_digest: None,
            state: RuntimeState::Running,
            health: RuntimeHealth::Healthy,
            runtime_object_id: Some(container.into()),
        })
    }

    pub(super) async fn observe_gateway_generation(
        &self,
        container: &str,
        endpoint: &str,
    ) -> Result<Vec<u8>, DriverError> {
        validate_name(container)?;
        let output = self
            .command(
                "podman",
                ["exec", container, "wget", "-qO-", endpoint],
                None,
            )
            .await?;
        if output.len() > 1024 {
            return Err(DriverError::internal(
                "gateway generation observation exceeded its bound",
            ));
        }
        Ok(output.into_bytes())
    }

    pub(super) async fn set_odoo_boot_selected(
        &self,
        slot: &str,
        selected: bool,
    ) -> Result<(), DriverError> {
        if !matches!(slot, "blue" | "green") {
            return Err(DriverError::bad("Odoo slot must be blue or green"));
        }
        let unit = format!("mb-odoo-{slot}");
        let path = self
            .root
            .join("odoo-slots")
            .join(format!("{unit}.container"));
        let mut source = std::fs::read_to_string(path).map_err(DriverError::internal)?;
        let install = "\n[Install]\nWantedBy=default.target\n";
        source = source.replace(install, "");
        if selected {
            source.push_str(install);
        }
        let image = source
            .lines()
            .find_map(|line| line.strip_prefix("Image="))
            .ok_or_else(|| DriverError::internal("Odoo Quadlet image is missing"))?
            .to_owned();
        let digest = source
            .lines()
            .find_map(|line| line.strip_prefix("Label=mb.config-digest="))
            .ok_or_else(|| DriverError::internal("Odoo Quadlet digest is missing"))?
            .to_owned();
        self.install_and_start(
            &format!("runtime/shared-odoo/{slot}"),
            "odoo-slots",
            &unit,
            &source,
            &image,
            &digest,
            selected,
        )
        .await?;
        if !selected {
            self.set_state(&unit, RuntimeState::Stopped).await?;
        }
        Ok(())
    }

    pub(super) async fn ensure_paperless(
        &self,
        desired: &PaperlessDesired,
    ) -> Result<RuntimeObservation, DriverError> {
        validate_digest_image(&desired.image)?;
        self.assert_image_role(&desired.image, &["paperless"])?;
        validate_digest(&desired.config_digest)?;
        validate_name(&desired.container_name)?;
        validate_environment(&desired.environment)?;
        validate_absolute_directory(&desired.secret_directory)?;
        validate_name(&desired.network)?;
        let unit = format!("mb-paperless-{}", desired.workshop.simple());
        let mut source = format!(
            "[Unit]\nDescription=MakersBrain Paperless {}\n\n[Container]\nContainerName={}\nImage={}\nPull=never\nNetwork={}\nGroupAdd=keep-groups\nReadOnly=true\nDropCapability=all\nNoNewPrivileges=true\nLabel=mb.kind=paperless\nLabel=mb.workshop={}\nLabel=mb.config-digest={}\nVolume={}:{}:ro\n",
            desired.workshop,
            desired.container_name,
            desired.image,
            desired.network,
            desired.workshop,
            desired.config_digest,
            desired.secret_directory.display(),
            "/run/mb-secrets",
        );
        append_environment(&mut source, &desired.environment);
        for (volume, target) in &desired.volumes {
            validate_name(volume)?;
            validate_absolute_directory(Path::new(target))?;
            source.push_str(&format!("Volume={volume}:{target}\n"));
        }
        source.push_str("Tmpfs=/tmp:rw,noexec,nosuid,size=64m\nHealthCmd=/usr/bin/curl --fail --silent http://127.0.0.1:8000/api/\nHealthInterval=10s\nHealthRetries=12\nNotify=healthy\n\n[Service]\nRestart=always\nRestartSec=5s\nTimeoutStartSec=180s\n\n[Install]\nWantedBy=default.target\n");
        self.install_and_start(
            &format!("workshop/{}/paperless", desired.workshop),
            "paperless",
            &unit,
            &source,
            &desired.image,
            &desired.config_digest,
            true,
        )
        .await
    }

    pub(super) async fn ensure_odoo_slot(
        &self,
        desired: &OdooSlotDesired,
    ) -> Result<RuntimeObservation, DriverError> {
        if !matches!(desired.slot.as_str(), "blue" | "green") {
            return Err(DriverError::bad("Odoo slot must be blue or green"));
        }
        for name in [
            &desired.container_name,
            &desired.extension_volume,
            &desired.data_volume,
            &desired.network,
        ] {
            validate_name(name)?;
        }
        validate_digest_image(&desired.image)?;
        self.assert_image_role(&desired.image, &["odoo"])?;
        validate_digest(&desired.config_digest)?;
        validate_environment(&desired.environment)?;
        validate_absolute_directory(&desired.secret_directory)?;
        validate_absolute_directory(&desired.client_secret_directory)?;
        if desired
            .postgres_ca
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(DriverError::internal("unsafe PostgreSQL CA path"));
        }
        let unit = format!("mb-odoo-{}", desired.slot);
        let port = if desired.slot == "blue" { 18069 } else { 18070 };
        let mut source = format!(
            "[Unit]\nDescription=MakersBrain Odoo {} slot\n\n[Container]\nContainerName={}\nImage={}\nPull=never\nNetwork={}\nGroupAdd=keep-groups\nReadOnly=true\nDropCapability=all\nNoNewPrivileges=true\nLabel=mb.kind=odoo-release-runtime\nLabel=mb.image-digest={}\nLabel=mb.config-digest={}\nVolume={}:/run/mb-release-secrets:ro\nVolume={}:/run/mb-odoo-client-secrets:ro\nVolume={}:/opt/mb-extension:ro\nVolume={}:/var/lib/odoo\nTmpfs=/tmp:rw,noexec,nosuid,size=64m\nTmpfs=/var/run/odoo:rw,noexec,nosuid,size=16m\nPublishPort=127.0.0.1:{port}:8069\n",
            desired.slot,
            desired.container_name,
            desired.image,
            desired.network,
            desired.image,
            desired.config_digest,
            desired.secret_directory.display(),
            desired.client_secret_directory.display(),
            desired.extension_volume,
            desired.data_volume,
        );
        if let Some(ca) = &desired.postgres_ca {
            source.push_str(&format!(
                "Volume={}:/run/mb-postgres-ca/postgres-ca.crt:ro\n",
                ca.display()
            ));
        }
        append_environment(&mut source, &desired.environment);
        source.push_str("\n[Service]\nRestart=always\nRestartSec=5s\nTimeoutStartSec=180s\n");
        if desired.boot_selected {
            source.push_str("\n[Install]\nWantedBy=default.target\n");
        }
        self.install_and_start(
            &format!("runtime/shared-odoo/{}", desired.slot),
            "odoo-slots",
            &unit,
            &source,
            &desired.image,
            &desired.config_digest,
            true,
        )
        .await
    }

    pub(super) async fn set_state(
        &self,
        unit: &str,
        state: RuntimeState,
    ) -> Result<(), DriverError> {
        validate_name(unit)?;
        match state {
            RuntimeState::Running => self.systemctl(["start", &format!("{unit}.service")]).await,
            RuntimeState::Stopped => self.systemctl(["stop", &format!("{unit}.service")]).await,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn install_and_start(
        &self,
        resource_key: &str,
        category: &str,
        unit: &str,
        source: &str,
        image: &str,
        desired_digest: &str,
        start: bool,
    ) -> Result<RuntimeObservation, DriverError> {
        validate_resource_key(resource_key)?;
        validate_name(unit)?;
        let generation_digest = format!("{:x}", Sha256::digest(source.as_bytes()));
        let candidate = self
            .runtime_dir
            .join("quadlet-candidates")
            .join(format!("{unit}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&candidate).map_err(DriverError::internal)?;
        std::fs::write(candidate.join(format!("{unit}.container")), source)
            .map_err(DriverError::internal)?;
        let verification = self
            .command(
                "/usr/lib/systemd/system-generators/podman-system-generator",
                ["--user", "--dryrun"],
                Some((&candidate, "QUADLET_UNIT_DIRS")),
            )
            .await;
        if let Err(error) = verification {
            let _ = std::fs::remove_dir_all(candidate);
            return Err(error);
        }
        let generation = self
            .root
            .join("generations")
            .join(unit)
            .join(&generation_digest);
        std::fs::create_dir_all(&generation).map_err(DriverError::internal)?;
        let generation_file = generation.join(format!("{unit}.container"));
        if generation_file.exists() {
            if std::fs::read_to_string(&generation_file).map_err(DriverError::internal)? != source {
                return Err(DriverError::internal(
                    "content-addressed Quadlet generation was modified",
                ));
            }
        } else {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(&generation_file, source).map_err(DriverError::internal)?;
            std::fs::set_permissions(&generation_file, std::fs::Permissions::from_mode(0o440))
                .map_err(DriverError::internal)?;
        }
        let selected_dir = self.root.join(category);
        std::fs::create_dir_all(&selected_dir).map_err(DriverError::internal)?;
        let selected = selected_dir.join(format!("{unit}.container"));
        let selected_existed = selected.exists();
        if !selected_existed {
            self.migrate_matching_raw_container(
                unit_container_name(source)?,
                image,
                desired_digest,
            )
            .await?;
        }
        let temporary = selected_dir.join(format!(".{unit}-{}.tmp", Uuid::new_v4()));
        symlink(&generation_file, &temporary).map_err(DriverError::internal)?;
        std::fs::rename(&temporary, selected).map_err(DriverError::internal)?;
        let _ = std::fs::remove_dir_all(candidate);
        self.systemctl(["daemon-reload"]).await?;
        let object = if start {
            self.systemctl(["start", &format!("{unit}.service")])
                .await?;
            Some(
                self.command(
                    "podman",
                    [
                        "inspect",
                        "--format",
                        "{{.Id}}",
                        unit_container_name(source)?,
                    ],
                    None,
                )
                .await?
                .trim()
                .into(),
            )
        } else {
            None
        };
        Ok(RuntimeObservation {
            resource_key: resource_key.into(),
            desired_digest: desired_digest.into(),
            observed_digest: Some(generation_digest),
            image_digest: Some(image.into()),
            state: if start {
                RuntimeState::Running
            } else {
                RuntimeState::Stopped
            },
            health: if start {
                RuntimeHealth::Healthy
            } else {
                RuntimeHealth::Unknown
            },
            runtime_object_id: object,
        })
    }

    fn assert_image_admitted(&self, image: &str) -> Result<(), DriverError> {
        for selection in ["active.json", "previous.json"] {
            let path = self.grant_root.join(selection);
            if !path.exists() {
                continue;
            }
            let grant: Value =
                serde_json::from_slice(&std::fs::read(&path).map_err(DriverError::internal)?)
                    .map_err(DriverError::internal)?;
            let images = grant
                .get("images")
                .and_then(Value::as_object)
                .ok_or_else(|| DriverError::internal("image grant has an invalid schema"))?;
            if images.values().any(|value| value.as_str() == Some(image)) {
                return Ok(());
            }
        }
        Err(DriverError::internal(
            "runtime image is not admitted by the active or previous release",
        ))
    }

    fn assert_image_role(&self, image: &str, roles: &[&str]) -> Result<(), DriverError> {
        for selection in ["active.json", "previous.json"] {
            let path = self.grant_root.join(selection);
            if !path.exists() {
                continue;
            }
            let grant: Value =
                serde_json::from_slice(&std::fs::read(&path).map_err(DriverError::internal)?)
                    .map_err(DriverError::internal)?;
            let images = grant
                .get("images")
                .and_then(Value::as_object)
                .ok_or_else(|| DriverError::internal("image grant has an invalid schema"))?;
            if roles
                .iter()
                .any(|role| images.get(*role).and_then(Value::as_str) == Some(image))
            {
                return Ok(());
            }
        }
        Err(DriverError::internal(
            "runtime image is not admitted for this resource kind",
        ))
    }

    async fn migrate_matching_raw_container(
        &self,
        container: &str,
        image: &str,
        config_digest: &str,
    ) -> Result<(), DriverError> {
        if !self.container_exists(container).await? {
            return Ok(());
        }
        if !self.allow_raw_migration {
            return Err(DriverError::internal(
                "a raw Podman runtime exists; staging migration requires DRIVER_ALLOW_RAW_PODMAN_MIGRATION=true",
            ));
        }
        let output = self.command("podman", ["inspect", container], None).await?;
        let values: Vec<Value> = serde_json::from_str(&output).map_err(DriverError::internal)?;
        let inspect = values
            .first()
            .ok_or_else(|| DriverError::internal("raw runtime inspection is empty"))?;
        let observed_image = inspect
            .get("ImageName")
            .or_else(|| inspect.pointer("/Config/Image"))
            .and_then(Value::as_str);
        let observed_digest = inspect
            .pointer("/Config/Labels/mb.config-digest")
            .and_then(Value::as_str);
        if observed_image != Some(image) || observed_digest != Some(config_digest) {
            return Err(DriverError::internal(
                "existing raw runtime identity does not match the verified Quadlet candidate",
            ));
        }
        self.command("podman", ["stop", "--time", "30", container], None)
            .await?;
        self.command("podman", ["rm", container], None).await?;
        Ok(())
    }

    async fn systemctl<const N: usize>(&self, args: [&str; N]) -> Result<(), DriverError> {
        self.command("systemctl", std::iter::once("--user").chain(args), None)
            .await
            .map(|_| ())
    }

    async fn command<I, S>(
        &self,
        executable: &str,
        args: I,
        extra_env: Option<(&Path, &str)>,
    ) -> Result<String, DriverError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command_with_timeout(executable, args, extra_env, Duration::from_secs(180))
            .await
    }

    async fn command_with_timeout<I, S>(
        &self,
        executable: &str,
        args: I,
        extra_env: Option<(&Path, &str)>,
        timeout: Duration,
    ) -> Result<String, DriverError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = tokio::process::Command::new(executable);
        command
            .args(args)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/bus", self.runtime_dir.display()),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some((value, name)) = extra_env {
            command.env(name, value);
        }
        let output = tokio::time::timeout(timeout, command.output())
            .await
            .map_err(|_| DriverError::internal("bounded runtime command timed out"))?
            .map_err(DriverError::internal)?;
        if output.stdout.len() + output.stderr.len() > 2 * 1024 * 1024 {
            return Err(DriverError::internal(
                "runtime command output exceeded its bound",
            ));
        }
        if !output.status.success() {
            return Err(DriverError::internal(format!(
                "bounded runtime command failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        String::from_utf8(output.stdout).map_err(DriverError::internal)
    }

    async fn command_success<I, S>(&self, executable: &str, args: I) -> Result<bool, DriverError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let status = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new(executable)
                .args(args)
                .env("XDG_RUNTIME_DIR", &self.runtime_dir)
                .env(
                    "DBUS_SESSION_BUS_ADDRESS",
                    format!("unix:path={}/bus", self.runtime_dir.display()),
                )
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
        )
        .await
        .map_err(|_| DriverError::internal("bounded runtime probe timed out"))?
        .map_err(DriverError::internal)?;
        Ok(status.success())
    }

    pub(super) async fn job_active(&self, container: &str) -> Result<bool, DriverError> {
        validate_name(container)?;
        let output = self
            .command(
                "systemctl",
                [
                    "--user",
                    "show",
                    "--property=LoadState",
                    "--property=ActiveState",
                    &format!("mb-job-{container}.service"),
                ],
                None,
            )
            .await?;
        parse_job_active(&output)
    }

    pub(super) async fn inspect_job(&self, container: &str) -> Result<Option<Value>, DriverError> {
        validate_name(container)?;
        if self.container_exists(container).await? {
            // If the object disappears between these calls, inspection fails
            // closed instead of converting a race into absence evidence.
            return self.inspect_container(container).await.map(Some);
        }
        if self.job_active(container).await? {
            return Err(DriverError::internal(
                "active runtime job has no inspectable identity",
            ));
        }
        Ok(None)
    }

    async fn command_bytes<I, S>(
        &self,
        executable: &str,
        args: I,
        input: Option<Bytes>,
        maximum_output: usize,
    ) -> Result<Vec<u8>, DriverError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut command = tokio::process::Command::new(executable);
        command
            .args(args)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/bus", self.runtime_dir.display()),
            )
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(DriverError::internal)?;
        if let Some(input) = input {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| DriverError::internal("runtime command stdin unavailable"))?;
            tokio::spawn(async move { stdin.write_all(&input).await });
        }
        let output = tokio::time::timeout(Duration::from_secs(180), child.wait_with_output())
            .await
            .map_err(|_| DriverError::internal("bounded archive command timed out"))?
            .map_err(DriverError::internal)?;
        if output.stdout.len() > maximum_output || output.stderr.len() > 2 * 1024 * 1024 {
            return Err(DriverError::internal(
                "archive command output exceeded its bound",
            ));
        }
        if !output.status.success() {
            return Err(DriverError::internal(format!(
                "archive command failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(output.stdout)
    }
}

fn parse_job_active(output: &str) -> Result<bool, DriverError> {
    let load = output
        .lines()
        .find_map(|line| line.strip_prefix("LoadState="));
    let active = output
        .lines()
        .find_map(|line| line.strip_prefix("ActiveState="));
    if load == Some("not-found") || matches!(active, Some("inactive" | "failed")) {
        Ok(false)
    } else if matches!(
        active,
        Some("active" | "activating" | "reloading" | "deactivating")
    ) {
        Ok(true)
    } else {
        Err(DriverError::internal(
            "runtime job systemd state is ambiguous",
        ))
    }
}

fn append_environment(source: &mut String, environment: &[(String, String)]) {
    for (key, value) in environment {
        source.push_str(&format!(
            "Environment={}={}\n",
            systemd_escape(key),
            systemd_escape(value)
        ));
    }
}

fn unit_container_name(source: &str) -> Result<&str, DriverError> {
    source
        .lines()
        .find_map(|line| line.strip_prefix("ContainerName="))
        .ok_or_else(|| DriverError::internal("generated Quadlet has no container name"))
}

fn validate_digest_image(value: &str) -> Result<(), DriverError> {
    digest_pinned_image("runtime image", value)
        .map(|_| ())
        .map_err(DriverError::internal)
}

fn validate_digest(value: &str) -> Result<(), DriverError> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(DriverError::internal(
            "invalid desired configuration digest",
        ))
    }
}

pub(super) fn validate_name(value: &str) -> Result<(), DriverError> {
    if (1..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        Ok(())
    } else {
        Err(DriverError::internal("unsafe deterministic runtime name"))
    }
}

fn validate_resource_key(value: &str) -> Result<(), DriverError> {
    if value.len() <= 180
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'/' | b'-' | b'_')
        })
    {
        Ok(())
    } else {
        Err(DriverError::internal("invalid closed runtime resource key"))
    }
}

fn validate_environment(environment: &[(String, String)]) -> Result<(), DriverError> {
    const ALLOWED: &[&str] = &[
        "HOST",
        "PORT",
        "USER",
        "ODOO_RC",
        "PYTHONPATH",
        "MB_CONTROL_API_URL",
        "MB_CONTROL_BRIDGE_TOKEN_FILE",
        "MB_ODOO_CLIENT_TOKEN_ROOT",
        "MB_CARRIER_CONTROL_TOKEN_ROOT",
        "PGSSLMODE",
        "PGSSLROOTCERT",
        "PAPERLESS_REDIS_FILE",
        "PAPERLESS_REDIS_PREFIX",
        "PAPERLESS_DBENGINE",
        "PAPERLESS_DBHOST",
        "PAPERLESS_DBPORT",
        "PAPERLESS_DBNAME",
        "PAPERLESS_DBUSER",
        "PAPERLESS_DBPASS_FILE",
        "PAPERLESS_SECRET_KEY_FILE",
        "PAPERLESS_URL",
        "PAPERLESS_TIME_ZONE",
        "PAPERLESS_OCR_LANGUAGE",
        "PAPERLESS_APPS",
        "PAPERLESS_SOCIALACCOUNT_PROVIDERS_FILE",
        "PAPERLESS_DISABLE_REGULAR_LOGIN",
        "PAPERLESS_REDIRECT_LOGIN_TO_SSO",
        "PAPERLESS_SOCIAL_AUTO_SIGNUP",
        "PAPERLESS_ADMIN_USER",
        "PAPERLESS_ADMIN_PASSWORD_FILE",
        "PAPERLESS_POST_CONSUME_SCRIPT",
        "PAPERLESS_WEBHOOK_SECRET_FILE",
        "MAKERSBRAIN_WORKSHOP_ID",
        "MAKERSBRAIN_CONTROL_URL",
        "PAPERLESS_DB_OPTIONS",
    ];
    if environment.iter().all(|(key, value)| {
        ALLOWED.contains(&key.as_str())
            && value.len() <= 4096
            && !value
                .chars()
                .any(|character| matches!(character, '\n' | '\r' | '\0'))
    }) {
        Ok(())
    } else {
        Err(DriverError::internal(
            "runtime environment is outside the closed schema",
        ))
    }
}

fn validate_job_environment(key: &str, value: &str) -> Result<(), DriverError> {
    const ALLOWED: &[&str] = &[
        "AGE_IDENTITY",
        "ARCHIVE_KEY",
        "AWS_DEFAULT_REGION",
        "BACKUP_PREFIX",
        "COMPLETE_KEY",
        "MANIFEST_KEY",
        "MB_BREAK_GLASS_PASSWORD_FILE",
        "MB_CONTROL_BRIDGE_TOKEN_FILE",
        "MB_ODOO_DATABASE",
        "ODOO_DATABASE",
        "ODOO_GID",
        "ODOO_RC",
        "ODOO_TEMPORARY",
        "ODOO_UID",
        "PAPERLESS_DATABASE",
        "PAPERLESS_OWNER",
        "PAPERLESS_TEMPORARY",
        "PAPERLESS_UID",
        "PGHOST",
        "PGAPPNAME",
        "PGPASSFILE",
        "PGPORT",
        "PGSSLROOTCERT",
        "PGSSLMODE",
        "PGUSER",
        "PORT",
        "PYTHONPATH",
        "S3_BUCKET",
        "S3_ENDPOINT",
        "S3_PREFIX",
        "USER",
    ];
    if ALLOWED.contains(&key)
        && value.len() <= 16 * 1024
        && !value
            .chars()
            .any(|character| matches!(character, '\n' | '\r' | '\0'))
    {
        Ok(())
    } else {
        Err(DriverError::internal(
            "job environment is outside the closed schema",
        ))
    }
}

fn validate_runtime_label(key: &str, value: &Value) -> Result<(), DriverError> {
    const ALLOWED: &[&str] = &[
        "mb.database",
        "mb.driver-fence",
        "mb.driver-operation",
        "mb.fleet-run",
        "mb.payload",
        "mb.release-adoption",
        "mb.workshop",
    ];
    let value = value
        .as_str()
        .ok_or_else(|| DriverError::internal("runtime label must be a string"))?;
    if !ALLOWED.contains(&key)
        || value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(DriverError::internal(
            "runtime label is outside the closed schema",
        ));
    }
    Ok(())
}

fn validate_cli_value(value: &str) -> Result<(), DriverError> {
    if value.len() <= 256 * 1024 && !value.contains('\0') {
        Ok(())
    } else {
        Err(DriverError::internal("unsafe runtime argument"))
    }
}

fn validate_name_or_none(value: &str) -> Result<(), DriverError> {
    if value == "none" {
        Ok(())
    } else {
        validate_name(value)
    }
}

fn validate_volume_value(value: &str) -> Result<(), DriverError> {
    validate_cli_value(value)?;
    let mut parts = value.split(':');
    let source = parts
        .next()
        .ok_or_else(|| DriverError::internal("job volume source is required"))?;
    let target = parts
        .next()
        .ok_or_else(|| DriverError::internal("job volume target is required"))?;
    if source.starts_with('/') {
        validate_absolute_directory(Path::new(source))?;
    } else {
        validate_name(source)?;
    }
    validate_absolute_directory(Path::new(target))?;
    if parts.any(|flags| !matches!(flags, "ro" | "rw" | "z" | "Z")) {
        return Err(DriverError::internal("invalid job volume flags"));
    }
    Ok(())
}

fn validate_absolute_directory(path: &Path) -> Result<(), DriverError> {
    if path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::RootDir | Component::Normal(_) | Component::CurDir
            )
        })
    {
        Ok(())
    } else {
        Err(DriverError::internal("unsafe runtime directory"))
    }
}

fn systemd_escape(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_environment_are_closed() {
        assert!(validate_name("mb-odoo-blue").is_ok());
        assert!(validate_name("../../host").is_err());
        assert!(validate_environment(&[("HOST".into(), "postgres.internal".into())]).is_ok());
        assert!(validate_environment(&[("LD_PRELOAD".into(), "/tmp/inject".into())]).is_err());
        assert!(validate_environment(&[("HOST".into(), "ok\nExecStart=bad".into())]).is_err());
        assert!(validate_job_environment("PGAPPNAME", "mb-release-v1-deadbeef").is_ok());
        assert!(validate_job_environment("PGAPPNAME", "bad\nname").is_err());
    }

    #[test]
    fn transient_runtime_labels_have_a_closed_schema() {
        assert!(validate_runtime_label("mb.fleet-run", &json!(Uuid::new_v4())).is_ok());
        assert!(validate_runtime_label("mb.driver-fence", &json!("42")).is_ok());
        assert!(validate_runtime_label("mb.untrusted", &json!("value")).is_err());
        assert!(validate_runtime_label("mb.fleet-run", &json!("bad\nvalue")).is_err());
    }

    #[test]
    fn transient_systemd_job_state_is_fail_closed() {
        assert!(parse_job_active("LoadState=loaded\nActiveState=active\n").unwrap());
        assert!(!parse_job_active("LoadState=loaded\nActiveState=failed\n").unwrap());
        assert!(!parse_job_active("LoadState=not-found\nActiveState=inactive\n").unwrap());
        assert!(parse_job_active("LoadState=loaded\nActiveState=unknown\n").is_err());
        assert!(parse_job_active("garbled").is_err());
    }

    #[test]
    fn only_active_or_previous_release_images_are_admitted() {
        let root = std::env::temp_dir().join(format!("mb-runtime-grant-{}", Uuid::new_v4()));
        let grants = root.join("grants");
        std::fs::create_dir_all(&grants).unwrap();
        let admitted = format!("registry.test/runtime@sha256:{}", "a".repeat(64));
        std::fs::write(
            grants.join("active.json"),
            serde_json::to_vec(&json!({"images":{"runtime":admitted.clone()}})).unwrap(),
        )
        .unwrap();
        let backend = QuadletBackend {
            root: root.join("quadlets"),
            runtime_dir: root.join("run"),
            grant_root: grants,
            allow_raw_migration: false,
        };
        assert!(backend.assert_image_admitted(&admitted).is_ok());
        assert!(
            backend
                .assert_image_admitted(&format!("registry.test/other@sha256:{}", "b".repeat(64)))
                .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn quadlet_workspace_inventory_is_keyset_paged() {
        let root = std::env::temp_dir().join(format!("mb-runtime-page-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("quadlets/paperless")).unwrap();
        std::fs::create_dir_all(root.join("quadlets/odoo-slots")).unwrap();
        for (category, unit) in [
            ("paperless", "mb-c"),
            ("odoo-slots", "mb-a"),
            ("paperless", "mb-b"),
        ] {
            std::fs::write(
                root.join("quadlets")
                    .join(category)
                    .join(format!("{unit}.container")),
                "[Container]\n",
            )
            .unwrap();
        }
        let backend = QuadletBackend {
            root: root.join("quadlets"),
            runtime_dir: root.join("run"),
            grant_root: root.join("grants"),
            allow_raw_migration: false,
        };

        assert_eq!(
            backend.workspace_resource_page(None, 2).unwrap(),
            vec!["mb-a", "mb-b"]
        );
        assert_eq!(
            backend.workspace_resource_page(Some("mb-b"), 2).unwrap(),
            vec!["mb-c"]
        );
        assert_eq!(
            backend.workspace_resources().unwrap(),
            vec!["mb-a", "mb-b", "mb-c"]
        );
        assert!(backend.workspace_resource_page(None, 0).is_err());
        assert!(
            backend
                .workspace_resource_page(Some("../escape"), 1)
                .is_err()
        );
        std::fs::write(
            root.join("quadlets/odoo-slots/mb-c.container"),
            "[Container]\n",
        )
        .unwrap();
        assert!(backend.workspace_resource_page(None, 2).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn quadlet_workspace_inventory_rejects_a_symlinked_category() {
        let root = std::env::temp_dir().join(format!("mb-runtime-page-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::fs::create_dir_all(root.join("quadlets")).unwrap();
        std::os::unix::fs::symlink(root.join("outside"), root.join("quadlets/paperless")).unwrap();
        let backend = QuadletBackend {
            root: root.join("quadlets"),
            runtime_dir: root.join("run"),
            grant_root: root.join("grants"),
            allow_raw_migration: false,
        };
        assert!(backend.workspace_resource_page(None, 1).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn quadlet_workspace_identity_lookup_is_direct_and_typed() {
        let root = std::env::temp_dir().join(format!("mb-runtime-lookup-{}", Uuid::new_v4()));
        std::fs::create_dir_all(root.join("quadlets/paperless")).unwrap();
        std::fs::create_dir_all(root.join("generation")).unwrap();
        std::fs::write(
            root.join("generation/mb-paperless-a.container"),
            "[Container]\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(
            root.join("generation/mb-paperless-a.container"),
            root.join("quadlets/paperless/mb-paperless-a.container"),
        )
        .unwrap();
        let backend = QuadletBackend {
            root: root.join("quadlets"),
            runtime_dir: root.join("run"),
            grant_root: root.join("grants"),
            allow_raw_migration: false,
        };
        assert!(backend.workspace_resource_exists("mb-paperless-a").unwrap());
        assert!(!backend.workspace_resource_exists("mb-odoo-blue").unwrap());
        assert!(backend.workspace_resource_exists("unowned-a").is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
