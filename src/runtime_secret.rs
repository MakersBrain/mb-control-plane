use std::path::Path;

const SECRET_REFERENCE_PREFIX: &str = "@/run/secrets/";
const MAXIMUM_SECRET_BYTES: u64 = 64 * 1024;

pub fn environment(name: &str) -> Result<Option<String>, String> {
    let raw = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("{name} is not valid UTF-8"));
        }
    };
    resolve(name, raw)
}

pub fn required(name: &str) -> Result<String, String> {
    environment(name)?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

pub fn configuration(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) => configuration_value(name, value).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} is not valid UTF-8")),
    }
}

fn configuration_value(name: &str, value: String) -> Result<String, String> {
    if value.starts_with('@') {
        Err(format!(
            "{name} is ordinary configuration and must not use a secret reference"
        ))
    } else {
        Ok(value)
    }
}

pub fn required_configuration(name: &str) -> Result<String, String> {
    configuration(name)?
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required"))
}

fn resolve(name: &str, raw: String) -> Result<Option<String>, String> {
    let Some(path) = raw.strip_prefix('@') else {
        return Err(format!(
            "{name} secret must use an explicit @/run/secrets/<leaf> reference"
        ));
    };
    let leaf = validate_secret_path(name, Path::new(path))?;
    read_secret(name, &mounted_secret_root().join(leaf)).map(Some)
}

fn mounted_secret_root() -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(root) = std::env::var_os("MAKERSBRAIN_TEST_SECRET_ROOT") {
        return root.into();
    }
    Path::new("/run/secrets").to_owned()
}

fn read_secret(name: &str, path: &Path) -> Result<String, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| format!("{name} secret reference is unavailable"))?;
    if !metadata.file_type().is_file() || metadata.len() > MAXIMUM_SECRET_BYTES {
        return Err(format!(
            "{name} secret reference is not a bounded regular file"
        ));
    }
    let mut value = std::fs::read_to_string(path)
        .map_err(|_| format!("{name} secret reference is unreadable UTF-8"))?;
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    if value.bytes().any(|byte| matches!(byte, 0 | b'\r' | b'\n')) {
        return Err(format!("{name} secret must contain exactly one text line"));
    }
    Ok(value)
}

fn validate_secret_path(name: &str, path: &Path) -> Result<String, String> {
    let rendered = path.to_string_lossy();
    let leaf = rendered
        .strip_prefix(SECRET_REFERENCE_PREFIX.trim_start_matches('@'))
        .ok_or_else(|| format!("{name} secret reference must be below /run/secrets"))?;
    if leaf.is_empty()
        || leaf.contains('/')
        || !leaf
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(format!("{name} secret reference has an unsafe path"));
    }
    Ok(leaf.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_secret_values_are_rejected() {
        assert!(resolve("FIXTURE", "direct-value".into()).is_err());
    }

    #[test]
    fn secret_references_are_not_ordinary_configuration() {
        let error = configuration_value("FIXTURE", "@/run/secrets/fixture".into()).unwrap_err();
        assert!(error.contains("must not use a secret reference"));
        assert_eq!(
            configuration_value("FIXTURE", "ordinary-value".into()).unwrap(),
            "ordinary-value"
        );
    }

    #[test]
    fn references_cannot_escape_the_secret_mount() {
        for value in ["@/tmp/value", "@/run/secrets/../value", "@relative"] {
            assert!(resolve("FIXTURE", value.into()).is_err(), "{value}");
        }
    }

    #[test]
    fn a_bounded_single_line_secret_is_read_without_its_newline() {
        let directory =
            std::env::temp_dir().join(format!("mb-runtime-secret-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("fixture");
        std::fs::write(&path, "recognizable-secret\n").unwrap();
        assert_eq!(
            read_secret("FIXTURE", &path).unwrap(),
            "recognizable-secret"
        );
        std::fs::write(&path, "first\nsecond\n").unwrap();
        assert!(read_secret("FIXTURE", &path).is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
