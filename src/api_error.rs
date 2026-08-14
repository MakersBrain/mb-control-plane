use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug)]
pub enum ApiError {
    Unauthenticated,
    Forbidden,
    NotFound,
    Conflict(&'static str),
    Validation(&'static str),
    Precondition(&'static str),
    PreconditionFailed(&'static str),
    PrivacyGate(&'static str),
    Gone(&'static str),
    Internal(anyhow::Error),
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            Self::Unauthenticated => (StatusCode::UNAUTHORIZED, "unauthenticated", None),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", None),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", None),
            Self::Conflict(message) => (StatusCode::CONFLICT, "conflict", Some(*message)),
            Self::Validation(message) => {
                (StatusCode::BAD_REQUEST, "validation_failed", Some(*message))
            }
            Self::Precondition(message) => (
                StatusCode::PRECONDITION_REQUIRED,
                "precondition_required",
                Some(*message),
            ),
            Self::PreconditionFailed(message) => (
                StatusCode::PRECONDITION_FAILED,
                "precondition_failed",
                Some(*message),
            ),
            Self::PrivacyGate(message) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "privacy_production_gate",
                Some(*message),
            ),
            Self::Gone(message) => (StatusCode::GONE, "gone", Some(*message)),
            Self::Internal(error) => {
                tracing::error!(error = %format_args!("{error:#}"), "request failed");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal", None)
            }
        };
        let mut response = (
            status,
            Json(ErrorBody {
                error: code,
                message,
            }),
        )
            .into_response();
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Bearer"),
            );
        }
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        );
        response.headers_mut().insert(
            header::REFERRER_POLICY,
            axum::http::HeaderValue::from_static("no-referrer"),
        );
        response
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::RowNotFound => Self::NotFound,
            error => Self::Internal(error.into()),
        }
    }
}
