pub mod azure;
pub mod odoo;
pub mod paperless;
pub mod rauthy;

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
    if response
        .content_length()
        .is_some_and(|size| size > maximum as u64)
    {
        return Err(IntegrationError::TooLarge);
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| IntegrationError::Unavailable)?;
    if body.len() > maximum {
        return Err(IntegrationError::TooLarge);
    }
    Ok(body.to_vec())
}
