pub mod azure;
pub mod cloudflare;
pub mod extraction;
pub mod inventory_vision;
pub mod odoo;
pub mod paperless;
pub mod product_lookup;
pub mod rauthy;
pub mod scaleway_tem;

use futures_util::StreamExt as _;
use reqwest::StatusCode;

use crate::domain::IntegrationError;

pub(crate) fn classify_status(status: StatusCode) -> IntegrationError {
    match status.as_u16() {
        400 | 409 | 422 => IntegrationError::Rejected,
        401 | 403 => IntegrationError::Unauthorized,
        404 => IntegrationError::NotFound,
        413 => IntegrationError::TooLarge,
        429 => IntegrationError::RateLimited {
            retry_after_seconds: None,
        },
        500..=599 => IntegrationError::Unavailable,
        _ => IntegrationError::ContractDrift,
    }
}

pub(crate) async fn bounded_body(
    response: reqwest::Response,
    maximum: usize,
) -> Result<Vec<u8>, IntegrationError> {
    let announced = response.content_length();
    if announced.is_some_and(|size| size > maximum as u64) {
        return Err(IntegrationError::TooLarge);
    }
    let capacity = announced
        .and_then(|size| usize::try_from(size).ok())
        .unwrap_or(0)
        .min(maximum);
    let mut body = Vec::with_capacity(capacity);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| IntegrationError::Unavailable)?;
        let next = body
            .len()
            .checked_add(chunk.len())
            .ok_or(IntegrationError::TooLarge)?;
        if next > maximum {
            return Err(IntegrationError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_statuses_have_stable_retry_and_safety_classes() {
        for (status, expected) in [
            (StatusCode::BAD_REQUEST, IntegrationError::Rejected),
            (StatusCode::UNAUTHORIZED, IntegrationError::Unauthorized),
            (StatusCode::FORBIDDEN, IntegrationError::Unauthorized),
            (StatusCode::NOT_FOUND, IntegrationError::NotFound),
            (StatusCode::PAYLOAD_TOO_LARGE, IntegrationError::TooLarge),
            (
                StatusCode::TOO_MANY_REQUESTS,
                IntegrationError::RateLimited {
                    retry_after_seconds: None,
                },
            ),
            (StatusCode::BAD_GATEWAY, IntegrationError::Unavailable),
            (StatusCode::IM_A_TEAPOT, IntegrationError::ContractDrift),
        ] {
            assert_eq!(classify_status(status), expected, "status {status}");
        }
        assert!(classify_status(StatusCode::TOO_MANY_REQUESTS).retryable());
        assert!(classify_status(StatusCode::SERVICE_UNAVAILABLE).retryable());
        assert!(!classify_status(StatusCode::UNAUTHORIZED).retryable());
        assert!(!classify_status(StatusCode::UNPROCESSABLE_ENTITY).retryable());
    }
}
