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

fn resolve(name: &str, raw: String) -> Result<Option<String>, String> {
    let Some(path) = raw.strip_prefix('@') else {
        return Ok(Some(raw));
    };
    let leaf = validate_secret_path(name, Path::new(path))?;
    read_secret(name, &Path::new("/run/secrets").join(leaf)).map(Some)
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
    fn direct_values_remain_compatible() {
        assert_eq!(
            resolve("FIXTURE", "direct-value".into()).unwrap(),
            Some("direct-value".into())
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
            std::env::temp_dir().join(format!("makersbrain-runtime-secret-{}", std::process::id()));
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
