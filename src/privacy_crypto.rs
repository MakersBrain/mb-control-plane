use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use base64::Engine;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use uuid::Uuid;

use crate::domain::IntegrationError;

const NONCE_BYTES: usize = 12;
pub(crate) const MAX_EXPORT_BYTES: usize = 128 * 1024 * 1024;

fn decode_key(encoded: &str) -> Result<LessSafeKey, IntegrationError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| IntegrationError::ContractDrift)?;
    if decoded.len() != 32 {
        return Err(IntegrationError::ContractDrift);
    }
    Ok(LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &decoded).map_err(|_| IntegrationError::ContractDrift)?,
    ))
}

fn key(environment: &str) -> Result<LessSafeKey, IntegrationError> {
    let encoded =
        crate::runtime_secret::required(environment).map_err(|_| IntegrationError::Unauthorized)?;
    decode_key(&encoded)
}

fn validate_key_id(value: String) -> Result<String, IntegrationError> {
    if !(1..=100).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(IntegrationError::ContractDrift);
    }
    Ok(value)
}

fn configured_key_id(environment: &str) -> Result<String, IntegrationError> {
    validate_key_id(
        crate::runtime_secret::required_configuration(environment)
            .map_err(|_| IntegrationError::Unauthorized)?,
    )
}

fn retained_export_keys() -> Result<std::collections::BTreeMap<String, String>, IntegrationError> {
    let path = std::env::var("CONTROL_PRIVACY_EXPORT_DECRYPTION_KEYS_FILE")
        .map_err(|_| IntegrationError::Unauthorized)?;
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(IntegrationError::ContractDrift);
    }
    let metadata = fs::symlink_metadata(&path).map_err(|_| IntegrationError::Unauthorized)?;
    if !metadata.file_type().is_file() || metadata.len() > 64 * 1024 {
        return Err(IntegrationError::ContractDrift);
    }
    let bytes = fs::read(path).map_err(|_| IntegrationError::Unauthorized)?;
    let values: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(&bytes).map_err(|_| IntegrationError::ContractDrift)?;
    if values.is_empty() || values.len() > 16 {
        return Err(IntegrationError::ContractDrift);
    }
    if values.contains_key(&export_key_id()?) {
        return Err(IntegrationError::ContractDrift);
    }
    for configured in values.keys() {
        validate_key_id(configured.clone())?;
    }
    for encoded in values.values() {
        let _ = decode_key(encoded)?;
    }
    Ok(values)
}

fn retained_export_key(key_id: &str) -> Result<LessSafeKey, IntegrationError> {
    let values = retained_export_keys()?;
    decode_key(values.get(key_id).ok_or(IntegrationError::Unauthorized)?)
}

pub(crate) fn validate_configuration() -> Result<(), IntegrationError> {
    let _ = lookup_key_id()?;
    let _ = key("CONTROL_PRIVACY_LOOKUP_KEY")?;
    Ok(())
}

pub(crate) fn validate_export_configuration() -> Result<(), IntegrationError> {
    let _ = export_key_id()?;
    let _ = key("CONTROL_PRIVACY_EXPORT_KEY")?;
    let _ = export_root()?;
    if std::env::var_os("CONTROL_PRIVACY_EXPORT_DECRYPTION_KEYS_FILE").is_some() {
        let _ = retained_export_keys()?;
    }
    Ok(())
}

pub(crate) fn lookup_key_id() -> Result<String, IntegrationError> {
    configured_key_id("CONTROL_PRIVACY_LOOKUP_KEY_ID")
}

pub(crate) fn export_key_id() -> Result<String, IntegrationError> {
    configured_key_id("CONTROL_PRIVACY_EXPORT_KEY_ID")
}

pub(crate) fn encrypt(
    tombstone: Uuid,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), IntegrationError> {
    encrypt_with("CONTROL_PRIVACY_LOOKUP_KEY", tombstone, plaintext, 4096)
}

pub(crate) fn encrypt_export(
    export: Uuid,
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), IntegrationError> {
    encrypt_with(
        "CONTROL_PRIVACY_EXPORT_KEY",
        export,
        plaintext,
        MAX_EXPORT_BYTES,
    )
}

fn export_root() -> Result<PathBuf, IntegrationError> {
    let configured =
        std::env::var("CONTROL_PRIVACY_EXPORT_ROOT").map_err(|_| IntegrationError::Unauthorized)?;
    let path = PathBuf::from(configured);
    if !path.is_absolute() {
        return Err(IntegrationError::ContractDrift);
    }
    fs::create_dir_all(&path).map_err(|_| IntegrationError::Unauthorized)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
            .map_err(|_| IntegrationError::Unauthorized)?;
    }
    fs::canonicalize(path).map_err(|_| IntegrationError::Unauthorized)
}

fn artifact_name(export: Uuid) -> String {
    format!("{export}.aead")
}

fn artifact_path(export: Uuid, storage_ref: &str) -> Result<PathBuf, IntegrationError> {
    if storage_ref != format!("file:{}", artifact_name(export)) {
        return Err(IntegrationError::ContractDrift);
    }
    Ok(export_root()?.join(artifact_name(export)))
}

pub(crate) fn store_export_artifact(
    export: Uuid,
    ciphertext: &[u8],
) -> Result<String, IntegrationError> {
    if !(17..=MAX_EXPORT_BYTES + 16).contains(&ciphertext.len()) {
        return Err(IntegrationError::TooLarge);
    }
    let root = export_root()?;
    let final_path = root.join(artifact_name(export));
    let temporary = root.join(format!(".{export}.{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let result = (|| -> std::io::Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(ciphertext)?;
        file.sync_all()?;
        fs::rename(&temporary, &final_path)?;
        OpenOptions::new().read(true).open(&root)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return Err(IntegrationError::Unavailable);
    }
    Ok(format!("file:{}", artifact_name(export)))
}

pub(crate) fn read_export_artifact(
    export: Uuid,
    storage_ref: &str,
) -> Result<Vec<u8>, IntegrationError> {
    let path = artifact_path(export, storage_ref)?;
    let metadata = fs::symlink_metadata(&path).map_err(|_| IntegrationError::NotFound)?;
    let length = usize::try_from(metadata.len()).map_err(|_| IntegrationError::TooLarge)?;
    if !metadata.file_type().is_file() || !(17..=MAX_EXPORT_BYTES + 16).contains(&length) {
        return Err(IntegrationError::ContractDrift);
    }
    let resolved = fs::canonicalize(&path).map_err(|_| IntegrationError::NotFound)?;
    let root = export_root()?;
    if resolved.parent() != Some(root.as_path()) {
        return Err(IntegrationError::ContractDrift);
    }
    let mut value = Vec::with_capacity(length);
    OpenOptions::new()
        .read(true)
        .open(resolved)
        .and_then(|file| {
            file.take((MAX_EXPORT_BYTES + 17) as u64)
                .read_to_end(&mut value)
        })
        .map_err(|_| IntegrationError::Unavailable)?;
    if value.len() != length {
        return Err(IntegrationError::ContractDrift);
    }
    Ok(value)
}

pub(crate) fn delete_export_artifact(
    export: Uuid,
    storage_ref: &str,
) -> Result<(), IntegrationError> {
    let path = artifact_path(export, storage_ref)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(IntegrationError::Unavailable),
    }
}

fn encrypt_with(
    environment: &str,
    context: Uuid,
    plaintext: &[u8],
    maximum: usize,
) -> Result<(Vec<u8>, Vec<u8>), IntegrationError> {
    if plaintext.is_empty() || plaintext.len() > maximum {
        return Err(IntegrationError::TooLarge);
    }
    let mut nonce_bytes = [0_u8; NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let mut ciphertext = plaintext.to_vec();
    key(environment)?
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(context.as_bytes()),
            &mut ciphertext,
        )
        .map_err(|_| IntegrationError::Unavailable)?;
    Ok((nonce_bytes.to_vec(), ciphertext))
}

pub(crate) fn decrypt(
    tombstone: Uuid,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, IntegrationError> {
    decrypt_with("CONTROL_PRIVACY_LOOKUP_KEY", tombstone, nonce, ciphertext)
}

#[cfg(test)]
fn decrypt_export(
    export: Uuid,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, IntegrationError> {
    decrypt_export_with_key_id(export, &export_key_id()?, nonce, ciphertext)
}

pub(crate) fn decrypt_export_with_key_id(
    export: Uuid,
    key_id: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, IntegrationError> {
    let current = export_key_id()?;
    let key = if key_id == current {
        key("CONTROL_PRIVACY_EXPORT_KEY")?
    } else {
        retained_export_key(key_id)?
    };
    decrypt_with_key(key, export, nonce, ciphertext)
}

fn decrypt_with(
    environment: &str,
    context: Uuid,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, IntegrationError> {
    decrypt_with_key(key(environment)?, context, nonce, ciphertext)
}

fn decrypt_with_key(
    key: LessSafeKey,
    context: Uuid,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, IntegrationError> {
    let nonce: [u8; NONCE_BYTES] = nonce
        .try_into()
        .map_err(|_| IntegrationError::ContractDrift)?;
    let mut plaintext = ciphertext.to_vec();
    let value = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(context.as_bytes()),
            &mut plaintext,
        )
        .map_err(|_| IntegrationError::Unauthorized)?;
    Ok(value.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    struct TestSecrets {
        root: PathBuf,
        names: Vec<&'static str>,
    }

    impl TestSecrets {
        fn new(entries: &[(&'static str, String)]) -> Self {
            let root = std::env::temp_dir()
                .join(format!("makersbrain-mounted-secrets-{}", Uuid::new_v4()));
            fs::create_dir(&root).unwrap();
            // SAFETY: privacy-crypto tests serialize access to these process
            // variables with environment_lock and this fixture removes them.
            unsafe { std::env::set_var("MAKERSBRAIN_TEST_SECRET_ROOT", &root) };
            let fixture = Self {
                root,
                names: entries.iter().map(|(name, _)| *name).collect(),
            };
            for (name, value) in entries {
                fixture.replace(name, value);
            }
            fixture
        }

        fn replace(&self, name: &'static str, value: &str) {
            let leaf = name.to_ascii_lowercase();
            fs::write(self.root.join(&leaf), value).unwrap();
            // SAFETY: see TestSecrets::new; the referenced path shape remains
            // the production @/run/secrets/<leaf> contract.
            unsafe { std::env::set_var(name, format!("@/run/secrets/{leaf}")) };
        }
    }

    impl Drop for TestSecrets {
        fn drop(&mut self) {
            for name in &self.names {
                // SAFETY: see TestSecrets::new.
                unsafe { std::env::remove_var(name) };
            }
            unsafe { std::env::remove_var("MAKERSBRAIN_TEST_SECRET_ROOT") };
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn environment_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn encrypted_lookup_is_bound_to_its_tombstone() {
        let _guard = environment_lock();
        let _secrets = TestSecrets::new(&[(
            "CONTROL_PRIVACY_LOOKUP_KEY",
            base64::engine::general_purpose::STANDARD.encode([7_u8; 32]),
        )]);
        let tombstone = Uuid::new_v4();
        let (nonce, ciphertext) = encrypt(tombstone, br#"{"rauthy_subject":"subject-1"}"#).unwrap();
        assert_ne!(ciphertext, br#"{"rauthy_subject":"subject-1"}"#);
        assert_eq!(
            decrypt(tombstone, &nonce, &ciphertext).unwrap(),
            br#"{"rauthy_subject":"subject-1"}"#
        );
        assert!(decrypt(Uuid::new_v4(), &nonce, &ciphertext).is_err());
    }

    #[test]
    fn export_ciphertext_uses_its_own_key_and_context() {
        let _guard = environment_lock();
        let _secrets = TestSecrets::new(&[
            (
                "CONTROL_PRIVACY_EXPORT_KEY",
                base64::engine::general_purpose::STANDARD.encode([9_u8; 32]),
            ),
            (
                "CONTROL_PRIVACY_LOOKUP_KEY",
                base64::engine::general_purpose::STANDARD.encode([7_u8; 32]),
            ),
        ]);
        unsafe {
            std::env::set_var("CONTROL_PRIVACY_EXPORT_KEY_ID", "current-export-key");
        }
        let export = Uuid::new_v4();
        let (nonce, ciphertext) = encrypt_export(export, br#"{"subject":"example"}"#).unwrap();
        assert_eq!(
            decrypt_export(export, &nonce, &ciphertext).unwrap(),
            br#"{"subject":"example"}"#
        );
        assert!(decrypt_export(Uuid::new_v4(), &nonce, &ciphertext).is_err());
        assert!(decrypt(export, &nonce, &ciphertext).is_err());
        unsafe {
            std::env::remove_var("CONTROL_PRIVACY_EXPORT_KEY_ID");
        }
    }

    #[test]
    fn export_artifacts_are_private_exactly_scoped_and_deletable() {
        let _guard = environment_lock();
        let root = std::env::temp_dir().join(format!("makersbrain-export-test-{}", Uuid::new_v4()));
        let _secrets = TestSecrets::new(&[(
            "CONTROL_PRIVACY_EXPORT_KEY",
            base64::engine::general_purpose::STANDARD.encode([9_u8; 32]),
        )]);
        unsafe {
            std::env::set_var("CONTROL_PRIVACY_EXPORT_ROOT", &root);
            std::env::set_var("CONTROL_PRIVACY_EXPORT_KEY_ID", "current-export-key");
        }
        let export = Uuid::new_v4();
        let plaintext = br#"{"processor":"paperless","document":"content"}"#;
        let (nonce, ciphertext) = encrypt_export(export, plaintext).unwrap();
        let storage_ref = store_export_artifact(export, &ciphertext).unwrap();
        assert_eq!(storage_ref, format!("file:{export}.aead"));
        assert_eq!(
            decrypt_export(
                export,
                &nonce,
                &read_export_artifact(export, &storage_ref).unwrap()
            )
            .unwrap(),
            plaintext
        );
        assert!(read_export_artifact(export, "file:../escape.aead").is_err());
        assert!(read_export_artifact(Uuid::new_v4(), &storage_ref).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(root.join(format!("{export}.aead")))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        delete_export_artifact(export, &storage_ref).unwrap();
        assert!(!root.join(format!("{export}.aead")).exists());
        fs::remove_dir(&root).unwrap();
        unsafe {
            std::env::remove_var("CONTROL_PRIVACY_EXPORT_ROOT");
            std::env::remove_var("CONTROL_PRIVACY_EXPORT_KEY_ID");
        }
    }

    #[test]
    fn planned_rotation_can_decrypt_a_bounded_retained_export_key() {
        let _guard = environment_lock();
        let key_file =
            std::env::temp_dir().join(format!("makersbrain-export-keys-{}.json", Uuid::new_v4()));
        let old_key = base64::engine::general_purpose::STANDARD.encode([4_u8; 32]);
        let secrets = TestSecrets::new(&[("CONTROL_PRIVACY_EXPORT_KEY", old_key.clone())]);
        unsafe {
            std::env::set_var("CONTROL_PRIVACY_EXPORT_KEY_ID", "old-export-key");
        }
        let export = Uuid::new_v4();
        let (nonce, ciphertext) = encrypt_export(export, b"planned rotation").unwrap();
        fs::write(
            &key_file,
            serde_json::to_vec(&serde_json::json!({"old-export-key":old_key})).unwrap(),
        )
        .unwrap();
        secrets.replace(
            "CONTROL_PRIVACY_EXPORT_KEY",
            &base64::engine::general_purpose::STANDARD.encode([5_u8; 32]),
        );
        unsafe {
            std::env::set_var("CONTROL_PRIVACY_EXPORT_KEY_ID", "new-export-key");
            std::env::set_var("CONTROL_PRIVACY_EXPORT_DECRYPTION_KEYS_FILE", &key_file);
        }
        assert_eq!(
            decrypt_export_with_key_id(export, "old-export-key", &nonce, &ciphertext).unwrap(),
            b"planned rotation"
        );
        assert!(decrypt_export_with_key_id(export, "unknown-key", &nonce, &ciphertext).is_err());
        fs::remove_file(key_file).unwrap();
        unsafe {
            std::env::remove_var("CONTROL_PRIVACY_EXPORT_KEY_ID");
            std::env::remove_var("CONTROL_PRIVACY_EXPORT_DECRYPTION_KEYS_FILE");
        }
    }

    #[test]
    fn retained_export_ring_cannot_duplicate_the_active_key() {
        let _guard = environment_lock();
        let key_file =
            std::env::temp_dir().join(format!("makersbrain-export-keys-{}.json", Uuid::new_v4()));
        let current_key = base64::engine::general_purpose::STANDARD.encode([6_u8; 32]);
        fs::write(
            &key_file,
            serde_json::to_vec(&serde_json::json!({"current-export-key":current_key})).unwrap(),
        )
        .unwrap();
        unsafe {
            std::env::set_var("CONTROL_PRIVACY_EXPORT_KEY_ID", "current-export-key");
            std::env::set_var("CONTROL_PRIVACY_EXPORT_DECRYPTION_KEYS_FILE", &key_file);
        }
        assert!(matches!(
            retained_export_keys(),
            Err(IntegrationError::ContractDrift)
        ));
        fs::remove_file(key_file).unwrap();
        unsafe {
            std::env::remove_var("CONTROL_PRIVACY_EXPORT_KEY_ID");
            std::env::remove_var("CONTROL_PRIVACY_EXPORT_DECRYPTION_KEYS_FILE");
        }
    }
}
