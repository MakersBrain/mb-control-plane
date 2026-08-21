use std::collections::HashMap;
use std::path::Path;

use base64::Engine;
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

const ISSUER: &str = "mb-control";
const AUDIENCE: &str = "mb-invitation";
const MEDIA_TYPE: &str = "mb-invitation+jwt";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvitationClaims {
    pub iss: String,
    pub aud: String,
    pub jti: Uuid,
    pub r#gen: i32,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

pub struct InvitationSigner {
    current_key_id: String,
    keys: HashMap<String, EncodingKey>,
}

pub struct InvitationVerifier {
    keys: HashMap<String, DecodingKey>,
}

#[derive(Debug, Error)]
pub enum InvitationTokenError {
    #[error("invitation key configuration is invalid")]
    KeyConfiguration,
    #[error("invitation token is invalid")]
    Invalid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationKeySet {
    keys: HashMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningKeySet {
    keys: HashMap<String, String>,
}

impl InvitationSigner {
    pub fn from_json_file(
        current_key_id: String,
        path: &Path,
    ) -> Result<Self, InvitationTokenError> {
        if current_key_id.trim().is_empty() {
            return Err(InvitationTokenError::KeyConfiguration);
        }
        let bytes = std::fs::read(path).map_err(|_| InvitationTokenError::KeyConfiguration)?;
        let configured: SigningKeySet =
            serde_json::from_slice(&bytes).map_err(|_| InvitationTokenError::KeyConfiguration)?;
        let mut keys = HashMap::new();
        for (key_id, encoded) in configured.keys {
            if key_id.trim().is_empty() {
                return Err(InvitationTokenError::KeyConfiguration);
            }
            let der = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| InvitationTokenError::KeyConfiguration)?;
            keys.insert(key_id, EncodingKey::from_ed_der(&der));
        }
        if !keys.contains_key(&current_key_id) {
            return Err(InvitationTokenError::KeyConfiguration);
        }
        Ok(Self {
            current_key_id,
            keys,
        })
    }

    pub fn sign(
        &self,
        invitation_id: Uuid,
        generation: i32,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<String, InvitationTokenError> {
        self.sign_with_key_id(
            &self.current_key_id,
            invitation_id,
            generation,
            issued_at,
            expires_at,
        )
    }

    pub fn sign_with_key_id(
        &self,
        key_id: &str,
        invitation_id: Uuid,
        generation: i32,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<String, InvitationTokenError> {
        if generation < 1 || expires_at <= issued_at {
            return Err(InvitationTokenError::Invalid);
        }
        let key = self
            .keys
            .get(key_id)
            .ok_or(InvitationTokenError::KeyConfiguration)?;
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(key_id.to_owned());
        header.typ = Some(MEDIA_TYPE.into());
        let issued_at = issued_at.unix_timestamp();
        let claims = InvitationClaims {
            iss: ISSUER.into(),
            aud: AUDIENCE.into(),
            jti: invitation_id,
            r#gen: generation,
            iat: issued_at,
            nbf: issued_at,
            exp: expires_at.unix_timestamp(),
        };
        encode(&header, &claims, key).map_err(|_| InvitationTokenError::Invalid)
    }

    pub fn key_id(&self) -> &str {
        &self.current_key_id
    }
}

impl InvitationVerifier {
    pub fn from_json_file(path: &Path) -> Result<Self, InvitationTokenError> {
        let bytes = std::fs::read(path).map_err(|_| InvitationTokenError::KeyConfiguration)?;
        let configured: VerificationKeySet =
            serde_json::from_slice(&bytes).map_err(|_| InvitationTokenError::KeyConfiguration)?;
        if configured.keys.is_empty() {
            return Err(InvitationTokenError::KeyConfiguration);
        }
        let mut keys = HashMap::new();
        for (key_id, encoded) in configured.keys {
            if key_id.trim().is_empty() {
                return Err(InvitationTokenError::KeyConfiguration);
            }
            let der = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| InvitationTokenError::KeyConfiguration)?;
            keys.insert(key_id, DecodingKey::from_ed_der(&der));
        }
        Ok(Self { keys })
    }

    pub fn verify(&self, token: &str) -> Result<InvitationClaims, InvitationTokenError> {
        if token.len() > 4096 {
            return Err(InvitationTokenError::Invalid);
        }
        let header = decode_header(token).map_err(|_| InvitationTokenError::Invalid)?;
        if header.alg != Algorithm::EdDSA || header.typ.as_deref() != Some(MEDIA_TYPE) {
            return Err(InvitationTokenError::Invalid);
        }
        let key_id = header.kid.ok_or(InvitationTokenError::Invalid)?;
        let key = self
            .keys
            .get(&key_id)
            .ok_or(InvitationTokenError::Invalid)?;
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[ISSUER]);
        validation.set_audience(&[AUDIENCE]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "nbf"]);
        validation.leeway = 30;
        let claims = decode::<InvitationClaims>(token, key, &validation)
            .map_err(|_| InvitationTokenError::Invalid)?
            .claims;
        if claims.r#gen < 1 || claims.exp <= claims.iat || claims.nbf != claims.iat {
            return Err(InvitationTokenError::Invalid);
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIVATE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-fixtures/invitation-private.pem"
    ));

    #[test]
    fn token_round_trip_is_versioned_and_asymmetric() {
        let signer = InvitationSigner {
            current_key_id: "test-1".into(),
            keys: HashMap::from([("test-1".into(), EncodingKey::from_ed_pem(PRIVATE).unwrap())]),
        };
        let public = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-fixtures/invitation-public.pem"
        ));
        let verifier = InvitationVerifier {
            keys: HashMap::from([("test-1".into(), DecodingKey::from_ed_pem(public).unwrap())]),
        };
        let invitation = Uuid::new_v4();
        let issued = OffsetDateTime::now_utc();
        let token = signer
            .sign(invitation, 3, issued, issued + time::Duration::hours(1))
            .unwrap();
        let claims = verifier.verify(&token).unwrap();
        assert_eq!(claims.jti, invitation);
        assert_eq!(claims.r#gen, 3);
        assert!(!token.contains(&invitation.to_string()));
    }

    #[test]
    fn queued_events_can_use_a_retained_rotation_key() {
        let key = EncodingKey::from_ed_pem(PRIVATE).unwrap();
        let signer = InvitationSigner {
            current_key_id: "new-key".into(),
            keys: HashMap::from([("old-key".into(), key.clone()), ("new-key".into(), key)]),
        };
        let issued = OffsetDateTime::now_utc();
        let token = signer
            .sign_with_key_id(
                "old-key",
                Uuid::new_v4(),
                1,
                issued,
                issued + time::Duration::hours(1),
            )
            .unwrap();
        assert_eq!(
            decode_header(&token).unwrap().kid.as_deref(),
            Some("old-key")
        );
    }
}
