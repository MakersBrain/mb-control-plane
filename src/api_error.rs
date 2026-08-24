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
                let (error_classes, error_chain_truncated) =
                    crate::error_reporting::safe_anyhow_chain(error);
                tracing::error!(?error_classes, error_chain_truncated, "request failed");
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::response::IntoResponse as _;
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::*;

    #[derive(Clone, Default)]
    struct RecordedEvents(Arc<Mutex<Vec<String>>>);

    struct EventVisitor<'a>(&'a mut String);

    impl Visit for EventVisitor<'_> {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write as _;
            let _ = write!(self.0, "{}={value:?};", field.name());
        }
    }

    impl<S: Subscriber> Layer<S> for RecordedEvents {
        fn on_event(&self, event: &Event<'_>, _context: tracing_subscriber::layer::Context<'_, S>) {
            let mut rendered = String::new();
            event.record(&mut EventVisitor(&mut rendered));
            self.0.lock().expect("recorded event lock").push(rendered);
        }
    }

    #[test]
    fn internal_error_logs_use_bounded_classes_without_sensitive_messages() {
        const TOKEN: &str = "Bearer log-redaction-token";
        const EMAIL: &str = "subject@example.test";
        const PAYLOAD: &str = "{\"document\":\"private invoice\"}";
        const SECRET_PATH: &str = "/run/secrets/control-api-token";
        let canary = format!("{TOKEN} {EMAIL} {PAYLOAD} {SECRET_PATH}");
        let recorded = RecordedEvents::default();
        let subscriber = tracing_subscriber::registry().with(recorded.clone());

        tracing::subscriber::with_default(subscriber, || {
            let response = ApiError::Internal(anyhow::anyhow!(canary)).into_response();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        });

        let rendered = recorded.0.lock().expect("recorded event lock").join("\n");
        assert!(rendered.contains("error_classes"));
        for sensitive in [TOKEN, EMAIL, PAYLOAD, SECRET_PATH] {
            assert!(
                !rendered.contains(sensitive),
                "captured log leaked {sensitive}"
            );
        }
    }
}
