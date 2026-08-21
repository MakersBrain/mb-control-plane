use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct FileInventory {
    path: String,
    size: u64,
    mode: u32,
    sha256: String,
}

#[derive(Deserialize)]
struct PayloadManifest {
    schema: String,
    payload_digest: String,
    files: Vec<FileInventory>,
}

struct Limits {
    files: usize,
    file_bytes: u64,
    bytes: u64,
}

fn main() -> anyhow::Result<()> {
    let arguments: Vec<String> = std::env::args().collect();
    let seal = match arguments.get(1).map(String::as_str) {
        Some("seal") => true,
        Some("verify") => false,
        _ => bail!("the extension helper only supports seal or verify"),
    };
    let staged = required_path(&arguments, "--staged")?;
    let target = required_path(&arguments, "--target")?;
    let manifest_path = required_path(&arguments, "--manifest")?;
    let expected_payload = required(&arguments, "--expected-payload")?;
    let marker = required_path(&arguments, "--write-marker-last")?;
    let limits = Limits {
        files: required(&arguments, "--max-files")?.parse()?,
        file_bytes: required(&arguments, "--max-file-bytes")?.parse()?,
        bytes: required(&arguments, "--max-bytes")?.parse()?,
    };
    if staged != target
        || marker.parent() != Some(target.as_path())
        || (seal && marker.exists())
        || (!seal && !marker.is_file())
    {
        bail!("completion marker state is invalid");
    }
    let top: BTreeSet<_> = fs::read_dir(&staged)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<_, _>>()?;
    let expected_top = if seal {
        ["addons", "manifest.json", "python"].as_slice()
    } else {
        [".mb-complete", "addons", "manifest.json", "python"].as_slice()
    }
    .iter()
    .map(|value| (*value).into())
    .collect();
    if top != expected_top {
        bail!("extension payload has unexpected top-level paths");
    }
    for directory in [staged.join("addons"), staged.join("python")] {
        if !fs::symlink_metadata(&directory)?.file_type().is_dir() {
            bail!("extension payload directory is absent");
        }
    }
    let manifest: PayloadManifest =
        serde_json::from_slice(&fs::read(&manifest_path).context("reading extension manifest")?)?;
    if manifest.schema != "makersbrain.odoo.extension-payload.v1" {
        bail!("unsupported extension payload schema");
    }
    let mut inventory = Vec::new();
    let mut total = 0_u64;
    for name in ["addons", "python"] {
        inventory_tree(
            &staged,
            &staged.join(name),
            &limits,
            &mut inventory,
            &mut total,
        )?;
    }
    inventory.sort();
    if inventory.len() > limits.files || total > limits.bytes {
        bail!("extension payload exceeds its declared resource limits");
    }
    let declared = manifest.files.into_iter().collect::<BTreeSet<_>>();
    let observed = inventory.iter().cloned().collect::<BTreeSet<_>>();
    if declared != observed || declared.len() != inventory.len() {
        bail!("extension file inventory differs from the extracted tree");
    }
    let canonical = serde_jcs::to_vec(&inventory)?;
    let digest = format!("sha256:{:x}", Sha256::digest(canonical));
    if digest != expected_payload || manifest.payload_digest != expected_payload {
        bail!("extension payload digest mismatch");
    }
    if !seal {
        if fs::read_to_string(&marker)? != format!("{expected_payload}\n") {
            bail!("extension completion marker does not match the payload");
        }
        return Ok(());
    }
    let marker_body = format!("{expected_payload}\n");
    let temporary = target.join(".mb-complete.tmp");
    fs::write(&temporary, marker_body.as_bytes())?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o444))?;
    fs::rename(temporary, marker)?;
    Ok(())
}

fn inventory_tree(
    root: &Path,
    path: &Path,
    limits: &Limits,
    inventory: &mut Vec<FileInventory>,
    total: &mut u64,
) -> anyhow::Result<()> {
    let mut entries = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            bail!("links are forbidden in an extension payload");
        }
        if metadata.uid() != 65_532 || metadata.gid() != 65_532 || metadata.mode() & 0o7022 != 0 {
            bail!("extension ownership or mode is unsafe");
        }
        if metadata.is_dir() {
            inventory_tree(root, &path, limits, inventory, total)?;
        } else if metadata.is_file() {
            if metadata.len() > limits.file_bytes {
                bail!("an extension file exceeds the individual size limit");
            }
            *total = total
                .checked_add(metadata.len())
                .context("payload byte count overflow")?;
            if inventory.len() >= limits.files || *total > limits.bytes {
                bail!("extension payload exceeds its resource limits");
            }
            let relative = path
                .strip_prefix(root)?
                .to_str()
                .context("payload path is not UTF-8")?;
            if relative
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            {
                bail!("extension path is unsafe");
            }
            let bytes = fs::read(&path)?;
            inventory.push(FileInventory {
                path: relative.to_owned(),
                size: metadata.len(),
                mode: metadata.mode() & 0o7777,
                sha256: format!("{:x}", Sha256::digest(bytes)),
            });
        } else {
            bail!("extension payload contains a non-regular file");
        }
    }
    Ok(())
}

fn required(arguments: &[String], name: &str) -> anyhow::Result<String> {
    let index = arguments
        .iter()
        .position(|value| value == name)
        .context("required helper option is absent")?;
    arguments
        .get(index + 1)
        .filter(|value| !value.is_empty())
        .cloned()
        .context("required helper option has no value")
}

fn required_path(arguments: &[String], name: &str) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(required(arguments, name)?);
    if !path.is_absolute() {
        bail!("helper paths must be absolute");
    }
    Ok(path)
}
