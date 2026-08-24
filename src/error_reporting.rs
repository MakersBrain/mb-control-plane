//! Privacy-safe error classification for structured logs.
//!
//! Error `Display` and `Debug` output is not a logging contract: database
//! constraint details, HTTP URLs, filesystem paths, and contextual anyhow
//! messages can all contain credentials or personal data. Runtime boundaries
//! log only these stable classes and keep the original error for control flow.

const MAX_ERROR_CHAIN_DEPTH: usize = 8;

pub fn safe_error_class(error: &(dyn std::error::Error + 'static)) -> &'static str {
    if let Some(error) = error.downcast_ref::<crate::domain::IntegrationError>() {
        error.failure_class()
    } else if error.is::<sqlx::Error>() {
        "database"
    } else if error.is::<reqwest::Error>() {
        "http_transport"
    } else if error.is::<serde_json::Error>() {
        "json_contract"
    } else if error.is::<std::io::Error>() {
        "io"
    } else if error.is::<url::ParseError>() {
        "url_contract"
    } else {
        "internal"
    }
}

pub fn safe_anyhow_chain(error: &anyhow::Error) -> (Vec<&'static str>, bool) {
    let mut chain = error
        .chain()
        .take(MAX_ERROR_CHAIN_DEPTH + 1)
        .map(safe_error_class)
        .collect::<Vec<_>>();
    let truncated = chain.len() > MAX_ERROR_CHAIN_DEPTH;
    chain.truncate(MAX_ERROR_CHAIN_DEPTH);
    (chain, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifications_are_stable_and_never_contain_error_messages() {
        let database =
            sqlx::Error::Protocol("subject@example.test Bearer secret /run/secrets/key".into());
        assert_eq!(safe_error_class(&database), "database");
        assert_eq!(
            safe_error_class(&crate::domain::IntegrationError::UnknownOutcome),
            "unknown_outcome"
        );

        let error = anyhow::Error::new(database).context("{\"private\":\"payload\"}");
        let (classes, truncated) = safe_anyhow_chain(&error);
        assert_eq!(classes, ["internal", "database"]);
        assert!(!truncated);
        let rendered = format!("{classes:?}");
        for canary in [
            "subject@example.test",
            "Bearer secret",
            "/run/secrets/key",
            "private",
        ] {
            assert!(!rendered.contains(canary));
        }
    }
}
