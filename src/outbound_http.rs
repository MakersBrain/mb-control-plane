use std::sync::OnceLock;
use std::time::Duration;

use reqwest::header::HeaderValue;

const EXTERNAL_API_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

static TENANT_SERVICE_CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();
static PAPERLESS_SERVICE_CLIENT: OnceLock<Result<reqwest::Client, String>> = OnceLock::new();

#[cfg(test)]
static TENANT_SERVICE_CLIENT_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static PAPERLESS_SERVICE_CLIENT_BUILDS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

fn bounded_builder(user_agent: &'static str) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(EXTERNAL_API_CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(user_agent)
}

/// Starts a client builder for adapters that call an external HTTP API.
///
/// This profile deliberately rejects redirects so credentials and request
/// bodies cannot be forwarded to a location chosen by a dependency. It uses
/// the workspace's Rustls/WebPKI Reqwest features, keeps Reqwest's environment
/// proxy discovery enabled, and bounds connection establishment separately
/// from the adapter-owned total request timeout.
///
/// Authentication, total timeout, response limits, and retries remain with the
/// adapter because their safety and latency requirements are provider-specific.
pub(crate) fn external_api_builder(user_agent: &'static str) -> reqwest::ClientBuilder {
    bounded_builder(user_agent)
}

/// Starts a client builder for credential-bearing calls to a platform-owned
/// service. Environment proxies are disabled so internal bearer credentials
/// cannot be routed through a process-global proxy configuration.
pub(crate) fn internal_service_builder(user_agent: &'static str) -> reqwest::ClientBuilder {
    bounded_builder(user_agent).no_proxy()
}

/// Returns the process-scoped transport pool used by workshop-owned Odoo
/// bridge adapters. These are platform-owned services carrying tenant
/// credentials, so the internal-service profile disables ambient proxies.
///
/// The pool deliberately has no total request timeout or authentication
/// defaults. Those values are tenant- and operation-specific, so adapters add
/// them to every request. Cloning `reqwest::Client` retains the same connection
/// pool rather than constructing a new transport.
pub(crate) fn tenant_service_client() -> anyhow::Result<reqwest::Client> {
    let client = TENANT_SERVICE_CLIENT.get_or_init(|| {
        #[cfg(test)]
        TENANT_SERVICE_CLIENT_BUILDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        internal_service_builder("mb-control-worker")
            .build()
            .map_err(|error| error.to_string())
    });
    client
        .as_ref()
        .cloned()
        .map_err(|error| anyhow::anyhow!(error.clone()))
}

/// Returns the Paperless-specific process pool. It has the same credential-safe
/// transport policy as the Odoo pool, but preserves Paperless's established
/// caller identity for provider-side diagnostics and policy.
pub(crate) fn paperless_service_client() -> anyhow::Result<reqwest::Client> {
    let client = PAPERLESS_SERVICE_CLIENT.get_or_init(|| {
        #[cfg(test)]
        PAPERLESS_SERVICE_CLIENT_BUILDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        internal_service_builder("mb-invoice-worker")
            .build()
            .map_err(|error| error.to_string())
    });
    client
        .as_ref()
        .cloned()
        .map_err(|error| anyhow::anyhow!(error.clone()))
}

/// Adds the current W3C trace context immediately before an outbound request is sent.
///
/// This belongs on the request builder rather than the client builder: clients are
/// long-lived, while the active span changes for every request and durable operation.
pub(crate) trait TraceRequestBuilderExt: Sized {
    fn with_current_trace_context(self) -> Self;
}

impl TraceRequestBuilderExt for reqwest::RequestBuilder {
    fn with_current_trace_context(self) -> Self {
        let context = crate::telemetry::current_trace_context();
        let mut request = self;
        let mut trace_parent_injected = false;

        if let Some(trace_parent) = context.trace_parent {
            match HeaderValue::from_str(&trace_parent) {
                Ok(mut value) => {
                    // Correlation identifiers are not credentials, but marking them
                    // sensitive keeps generic request debug output metadata-only.
                    value.set_sensitive(true);
                    request = request.header("traceparent", value);
                    trace_parent_injected = true;
                }
                Err(_) => tracing::warn!(
                    error_class = "outbound_trace_parent_invalid",
                    "outbound trace context was not injected"
                ),
            }
        }
        if trace_parent_injected && let Some(trace_state) = context.trace_state {
            match HeaderValue::from_str(&trace_state) {
                Ok(mut value) => {
                    value.set_sensitive(true);
                    request = request.header("tracestate", value);
                }
                Err(_) => tracing::warn!(
                    error_class = "outbound_trace_state_invalid",
                    "outbound trace state was not injected"
                ),
            }
        }
        tracing::trace!(
            trace_parent_injected,
            "outbound HTTP trace context prepared"
        );
        request
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use opentelemetry::trace::TracerProvider as _;
    use tracing::Instrument as _;
    use tracing::field::{Field, Visit};
    use tracing::{Event, Subscriber};
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt as _;
    use wiremock::matchers::{header, header_regex, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn tenant_service_transports_are_built_once_per_process() {
        tenant_service_client().expect("first shared tenant-service client");
        tenant_service_client().expect("second shared tenant-service client");
        paperless_service_client().expect("first shared Paperless client");
        paperless_service_client().expect("second shared Paperless client");
        assert_eq!(
            TENANT_SERVICE_CLIENT_BUILDS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            PAPERLESS_SERVICE_CLIENT_BUILDS.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

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
            self.0.lock().unwrap().push(rendered);
        }
    }

    #[tokio::test]
    async fn external_api_policy_identifies_the_caller_and_never_follows_redirects() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/redirect"))
            .and(header("user-agent", "mb-policy-test"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", format!("{}/credential-sink", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;

        let response = external_api_builder("mb-policy-test")
            .timeout(Duration::from_secs(2))
            .build()
            .expect("external API client")
            .get(format!("{}/redirect", server.uri()))
            .send()
            .await
            .expect("redirect response");

        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert_eq!(response.url().path(), "/redirect");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn outbound_request_propagates_trace_context_without_logging_credentials() {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let recorded = RecordedEvents::default();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("outbound-http-test")))
            .with(recorded.clone());
        let _subscriber = tracing::subscriber::set_default(subscriber);

        let inbound = std::collections::HashMap::from([
            (
                "traceparent".to_owned(),
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_owned(),
            ),
            ("tracestate".to_owned(), "vendor=value".to_owned()),
        ]);
        let remote_parent = opentelemetry::global::get_text_map_propagator(|propagator| {
            propagator.extract(&inbound)
        });
        let request_span = tracing::info_span!("representative_adapter_call");
        request_span.set_parent(remote_parent).unwrap();

        let server = MockServer::start().await;
        const SECRET: &str = "outbound-test-secret-must-not-be-logged";
        Mock::given(method("GET"))
            .and(path("/provider"))
            .and(header("authorization", format!("Bearer {SECRET}")))
            .and(header_regex(
                "traceparent",
                "^00-4bf92f3577b34da6a3ce929d0e0e4736-[0-9a-f]{16}-01$",
            ))
            .and(header("tracestate", "vendor=value"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        async {
            let client = external_api_builder("mb-policy-test")
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap();
            let request = client
                .get(format!("{}/provider", server.uri()))
                .bearer_auth(SECRET)
                .with_current_trace_context()
                .build()
                .unwrap();
            // Exercise the same Debug representation an adapter might record on
            // failure. Sensitive HeaderValue metadata must redact both credentials
            // and the correlation carrier.
            tracing::trace!(request = ?request, "test outbound request prepared");
            client.execute(request).await.unwrap();
        }
        .instrument(request_span)
        .await;

        let rendered = recorded.0.lock().unwrap().join("\n");
        assert!(rendered.contains("outbound HTTP trace context prepared"));
        assert!(!rendered.contains(SECRET));
        assert!(!rendered.contains("4bf92f3577b34da6a3ce929d0e0e4736"));

        drop(_subscriber);
        provider.shutdown().unwrap();
    }
}
