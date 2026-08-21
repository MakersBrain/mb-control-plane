//! Rauthy bearer verification and control-plane identity resolution.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::{HeaderMap, header};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
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
    use super::recent_strong_authentication;

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
}
