//! Rauthy bearer verification and control-plane identity resolution.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

use crate::api_error::ApiError;
use crate::domain::WorkshopRole;
use crate::persistence::Store;

const JWKS_MAX_BYTES: usize = 256 * 1024;
const CLOCK_LEEWAY_SECONDS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub user_id: Uuid,
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub recent_strong_authentication: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkshopAuthority {
    pub workshop_id: Uuid,
    pub role: WorkshopRole,
    pub epoch: i32,
}

#[derive(Debug, Clone)]
pub struct VerifiedToken {
    pub issuer: String,
    pub subject: String,
    pub email: String,
    pub recent_strong_authentication: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdToken {
    pub subject: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    #[allow(dead_code)]
    exp: i64,
    #[serde(rename = "typ")]
    token_type: String,
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    amr: Vec<String>,
    auth_time: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    aud: IdTokenAudience,
    #[allow(dead_code)]
    exp: i64,
    nonce: String,
    at_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IdTokenAudience {
    One(String),
    Many(Vec<String>),
}

struct VerificationKey {
    decoding: DecodingKey,
    algorithm: Algorithm,
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, Arc<VerificationKey>>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
    jwks_url: Option<Url>,
}

pub struct Authenticator {
    issuer: String,
    audience: String,
    discovery_url: Url,
    http: reqwest::Client,
    cache: RwLock<KeyCache>,
}

impl Authenticator {
    pub fn new(issuer: Url, audience: String, discovery_url: Url) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("mb-control-plane")
            .build()?;
        Ok(Self {
            issuer: issuer.to_string(),
            audience,
            discovery_url,
            http,
            cache: RwLock::new(KeyCache::default()),
        })
    }

    pub async fn warm(&self) -> anyhow::Result<()> {
        self.refresh().await
    }

    pub async fn ready(&self) -> bool {
        !self.cache.read().await.keys.is_empty()
    }

    pub async fn verify_headers(&self, headers: &HeaderMap) -> Result<VerifiedToken, ApiError> {
        let value = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| !value.is_empty())
            .ok_or(ApiError::Unauthenticated)?;
        self.verify(value).await
    }

    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
        store: &Store,
    ) -> Result<Principal, ApiError> {
        let token = self.verify_headers(headers).await?;
        let row = sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                Option<time::OffsetDateTime>,
                Option<time::OffsetDateTime>,
            ),
        >(
            "select u.id,u.email,u.disabled_at,i.disabled_at
             from control.external_identities i join control.users u on u.id=i.user_id
             where i.issuer=$1 and i.subject=$2",
        )
        .bind(&token.issuer)
        .bind(&token.subject)
        .fetch_optional(store.pool())
        .await?;
        let Some((user_id, email, user_disabled, identity_disabled)) = row else {
            return Err(ApiError::Unauthenticated);
        };
        if user_disabled.is_some() || identity_disabled.is_some() {
            return Err(ApiError::Unauthenticated);
        }
        Ok(Principal {
            user_id,
            issuer: token.issuer,
            subject: token.subject,
            email,
            recent_strong_authentication: token.recent_strong_authentication,
        })
    }

    /// Validate an authorization-code-flow ID token for one exact Odoo client.
    ///
    /// The audience is supplied by the trusted caller from the workshop path,
    /// never copied from the request body. OIDC permits `at_hash` to be absent
    /// for an ID token returned by the token endpoint; when Rauthy includes it,
    /// it remains a mandatory token-substitution check.
    pub async fn verify_id_token(
        &self,
        token: &str,
        access_token: &str,
        expected_nonce: &str,
        expected_audience: &str,
    ) -> Result<VerifiedIdToken, ApiError> {
        let header = decode_header(token).map_err(|_| ApiError::Unauthenticated)?;
        if header.alg != Algorithm::RS256 {
            return Err(ApiError::Unauthenticated);
        }
        let kid = header.kid.ok_or(ApiError::Unauthenticated)?;
        let key = self.key_for(&kid).await.map_err(|_| {
            tracing::warn!(
                error_class = "verification_key_unavailable",
                "unable to select ID-token verification key"
            );
            ApiError::Unauthenticated
        })?;
        if key.algorithm != Algorithm::RS256 {
            return Err(ApiError::Unauthenticated);
        }
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[expected_audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "nonce"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = CLOCK_LEEWAY_SECONDS;
        let claims = decode::<IdTokenClaims>(token, &key.decoding, &validation)
            .map_err(|_| ApiError::Unauthenticated)?
            .claims;
        let exact_audience = match &claims.aud {
            IdTokenAudience::One(value) => value == expected_audience,
            IdTokenAudience::Many(values) => {
                let _ = values;
                false
            }
        };
        if !exact_audience
            || claims.sub.trim().is_empty()
            || claims.sub.len() > 512
            || claims.sub.chars().any(char::is_control)
            || !constant_time_equal(claims.nonce.as_bytes(), expected_nonce.as_bytes())
        {
            return Err(ApiError::Unauthenticated);
        }
        if let Some(at_hash) = claims.at_hash {
            let expected = oidc_at_hash(access_token);
            if !constant_time_equal(at_hash.as_bytes(), expected.as_bytes()) {
                return Err(ApiError::Unauthenticated);
            }
        }
        Ok(VerifiedIdToken {
            subject: claims.sub,
        })
    }

    async fn verify(&self, token: &str) -> Result<VerifiedToken, ApiError> {
        let header = decode_header(token).map_err(|_| ApiError::Unauthenticated)?;
        let kid = header.kid.ok_or(ApiError::Unauthenticated)?;
        let key = self.key_for(&kid).await.map_err(|_| {
            tracing::warn!(
                error_class = "verification_key_unavailable",
                "unable to select token verification key"
            );
            ApiError::Unauthenticated
        })?;
        let mut validation = Validation::new(key.algorithm);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = CLOCK_LEEWAY_SECONDS;
        let claims = decode::<Claims>(token, &key.decoding, &validation)
            .map_err(|_| ApiError::Unauthenticated)?
            .claims;
        if claims.token_type != "Bearer" || !claims.email_verified {
            return Err(ApiError::Unauthenticated);
        }
        let email = crate::domain::normalize_email(
            claims.email.as_deref().ok_or(ApiError::Unauthenticated)?,
        )
        .map_err(|_| ApiError::Unauthenticated)?;
        let recent_strong_authentication = recent_strong_authentication(
            &claims.amr,
            claims.auth_time,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        );
        Ok(VerifiedToken {
            issuer: claims.iss,
            subject: claims.sub,
            email,
            recent_strong_authentication,
        })
    }

    async fn key_for(&self, kid: &str) -> anyhow::Result<Arc<VerificationKey>> {
        {
            let cache = self.cache.read().await;
            if cache
                .fetched_at
                .is_some_and(|at| at.elapsed() < Duration::from_secs(900))
                && let Some(key) = cache.keys.get(kid)
            {
                return Ok(key.clone());
            }
        }
        self.refresh().await?;
        self.cache
            .read()
            .await
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("unknown token key id"))
    }

    async fn refresh(&self) -> anyhow::Result<()> {
        {
            let cache = self.cache.read().await;
            if cache.fetched_at.is_some()
                && cache
                    .last_attempt
                    .is_some_and(|at| at.elapsed() < Duration::from_secs(30))
            {
                anyhow::bail!("JWKS refresh cooldown is active");
            }
        }
        let jwks_url = match self.cache.read().await.jwks_url.clone() {
            Some(url) => url,
            None => {
                let document: serde_json::Value = self.fetch_json(&self.discovery_url).await?;
                if document.get("issuer").and_then(|v| v.as_str()) != Some(&self.issuer) {
                    anyhow::bail!("OIDC discovery issuer mismatch");
                }
                let advertised = Url::parse(
                    document
                        .get("jwks_uri")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("OIDC discovery has no jwks_uri"))?,
                )?;
                let mut internal = self.discovery_url.clone();
                internal.set_path(advertised.path());
                internal.set_query(advertised.query());
                internal
            }
        };
        let set: jsonwebtoken::jwk::JwkSet = self.fetch_json(&jwks_url).await?;
        let mut keys = HashMap::new();
        for jwk in &set.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                continue;
            };
            let Some(algorithm) = jwk
                .common
                .key_algorithm
                .and_then(|value| Algorithm::try_from(value).ok())
            else {
                continue;
            };
            if !matches!(
                algorithm,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::ES256
                    | Algorithm::ES384
                    | Algorithm::EdDSA
            ) {
                continue;
            }
            if let Ok(decoding) = DecodingKey::from_jwk(jwk) {
                keys.insert(
                    kid,
                    Arc::new(VerificationKey {
                        decoding,
                        algorithm,
                    }),
                );
            }
        }
        if keys.is_empty() {
            anyhow::bail!("JWKS contains no supported verification keys");
        }
        let mut cache = self.cache.write().await;
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        cache.last_attempt = Some(Instant::now());
        cache.jwks_url = Some(jwks_url);
        Ok(())
    }

    async fn fetch_json<T: serde::de::DeserializeOwned>(&self, url: &Url) -> anyhow::Result<T> {
        let response = self
            .http
            .get(url.clone())
            .send()
            .await?
            .error_for_status()?;
        if response
            .content_length()
            .is_some_and(|size| size as usize > JWKS_MAX_BYTES)
        {
            anyhow::bail!("OIDC metadata exceeds size limit");
        }
        let bytes = response.bytes().await?;
        if bytes.len() > JWKS_MAX_BYTES {
            anyhow::bail!("OIDC metadata exceeds size limit");
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
}

fn oidc_at_hash(access_token: &str) -> String {
    let hash = Sha256::digest(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&hash[..hash.len() / 2])
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                ^ right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

fn recent_strong_authentication(amr: &[String], auth_time: Option<i64>, now: i64) -> bool {
    const MAX_AGE_SECONDS: i64 = 10 * 60;
    let Some(auth_time) = auth_time else {
        return false;
    };
    if auth_time > now.saturating_add(CLOCK_LEEWAY_SECONDS as i64)
        || now.saturating_sub(auth_time) > MAX_AGE_SECONDS
    {
        return false;
    }
    let has = |method: &str| amr.iter().any(|value| value.eq_ignore_ascii_case(method));
    has("mfa")
        || has("webauthn")
        || has("passkey")
        || has("fido2")
        || ((has("otp") || has("totp")) && has("pwd"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::rsa::KeySize;
    use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_SHA256, RsaKeyPair};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use jsonwebtoken::{Algorithm, DecodingKey};
    use serde_json::{Value, json};
    use url::Url;

    use super::{
        Authenticator, VerificationKey, constant_time_equal, oidc_at_hash,
        recent_strong_authentication,
    };

    fn signed_rs256_token(key: &RsaKeyPair, kid: &str, claims: Value) -> String {
        let header = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg":"RS256","kid":kid,"typ":"JWT"})).unwrap());
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header}.{claims}");
        let mut signature = vec![0_u8; key.public_modulus_len()];
        key.sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signing_input.as_bytes(),
            &mut signature,
        )
        .unwrap();
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    async fn id_token_authenticator(key: &RsaKeyPair, kid: &str) -> Authenticator {
        let authenticator = Authenticator::new(
            Url::parse("https://identity.example.test/").unwrap(),
            "control-api".into(),
            Url::parse("https://identity.internal/.well-known/openid-configuration").unwrap(),
        )
        .unwrap();
        let mut cache = authenticator.cache.write().await;
        cache.keys.insert(
            kid.into(),
            Arc::new(VerificationKey {
                decoding: DecodingKey::from_rsa_der(key.public_key().as_ref()),
                algorithm: Algorithm::RS256,
            }),
        );
        cache.fetched_at = Some(Instant::now());
        drop(cache);
        authenticator
    }

    #[test]
    fn step_up_requires_recent_strong_evidence() {
        let methods = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        };
        assert!(recent_strong_authentication(
            &methods(&["pwd", "mfa"]),
            Some(1_000),
            1_300
        ));
        assert!(recent_strong_authentication(
            &methods(&["webauthn"]),
            Some(1_000),
            1_300
        ));
        assert!(!recent_strong_authentication(
            &methods(&["pwd"]),
            Some(1_000),
            1_300
        ));
        assert!(!recent_strong_authentication(
            &methods(&["pwd", "mfa"]),
            Some(1_000),
            1_601
        ));
        assert!(!recent_strong_authentication(
            &methods(&["pwd", "mfa"]),
            None,
            1_300
        ));
    }

    #[test]
    fn authorization_code_at_hash_uses_the_oidc_rs256_rule() {
        // OpenID Connect Core's RS256 example access token and expected hash.
        assert_eq!(oidc_at_hash("SlAV32hkKG"), "rXH7QWVTZnXYCou_6Vdpfg");
        assert!(constant_time_equal(b"nonce", b"nonce"));
        assert!(!constant_time_equal(b"nonce", b"nonce2"));
    }

    #[tokio::test]
    async fn id_token_verification_binds_nonce_audience_and_optional_access_token_hash() {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let authenticator = id_token_authenticator(&key, "current-key").await;
        let audience = "mb-odoo-00112233445566778899aabbccddeeff";
        let access_token = "single-use-access-token";
        let claims = |nonce: &str, audience: &str, at_hash: Option<&str>| {
            let mut claims = json!({
                "iss":"https://identity.example.test/",
                "aud":audience,
                "sub":"stable-rauthy-subject",
                "exp":time::OffsetDateTime::now_utc().unix_timestamp() + 300,
                "nonce":nonce
            });
            if let Some(at_hash) = at_hash {
                claims["at_hash"] = Value::String(at_hash.into());
            }
            claims
        };

        let without_hash = signed_rs256_token(
            &key,
            "current-key",
            claims("expected-nonce", audience, None),
        );
        assert_eq!(
            authenticator
                .verify_id_token(&without_hash, access_token, "expected-nonce", audience)
                .await
                .unwrap()
                .subject,
            "stable-rauthy-subject"
        );

        let valid_hash = oidc_at_hash(access_token);
        let with_hash = signed_rs256_token(
            &key,
            "current-key",
            claims("expected-nonce", audience, Some(&valid_hash)),
        );
        assert!(
            authenticator
                .verify_id_token(&with_hash, access_token, "expected-nonce", audience)
                .await
                .is_ok()
        );
        assert!(
            authenticator
                .verify_id_token(&with_hash, "substituted", "expected-nonce", audience)
                .await
                .is_err()
        );
        let multiple_audiences = signed_rs256_token(
            &key,
            "current-key",
            json!({
                "iss":"https://identity.example.test/",
                "aud":[audience,"mb-odoo-another-workshop"],
                "sub":"stable-rauthy-subject",
                "exp":time::OffsetDateTime::now_utc().unix_timestamp() + 300,
                "nonce":"expected-nonce"
            }),
        );
        assert!(
            authenticator
                .verify_id_token(
                    &multiple_audiences,
                    access_token,
                    "expected-nonce",
                    audience
                )
                .await
                .is_err()
        );
        assert!(
            authenticator
                .verify_id_token(&with_hash, access_token, "wrong-nonce", audience)
                .await
                .is_err()
        );
        assert!(
            authenticator
                .verify_id_token(
                    &with_hash,
                    access_token,
                    "expected-nonce",
                    "mb-odoo-another-workshop",
                )
                .await
                .is_err()
        );
        let wrong_issuer = signed_rs256_token(
            &key,
            "current-key",
            json!({
                "iss":"https://substitute.example.test/",
                "aud":audience,
                "sub":"stable-rauthy-subject",
                "exp":time::OffsetDateTime::now_utc().unix_timestamp() + 300,
                "nonce":"expected-nonce"
            }),
        );
        assert!(
            authenticator
                .verify_id_token(&wrong_issuer, access_token, "expected-nonce", audience)
                .await
                .is_err()
        );
        let expired = signed_rs256_token(
            &key,
            "current-key",
            json!({
                "iss":"https://identity.example.test/",
                "aud":audience,
                "sub":"stable-rauthy-subject",
                "exp":time::OffsetDateTime::now_utc().unix_timestamp() - 300,
                "nonce":"expected-nonce"
            }),
        );
        assert!(
            authenticator
                .verify_id_token(&expired, access_token, "expected-nonce", audience)
                .await
                .is_err()
        );
        assert!(
            authenticator
                .verify_id_token("not-a-jwt", access_token, "expected-nonce", audience)
                .await
                .is_err()
        );
    }
}
