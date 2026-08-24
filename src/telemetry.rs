use std::collections::HashMap;

use opentelemetry::Context;
use opentelemetry::trace::TraceContextExt as _;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Keeps the optional OTLP provider alive and flushes it on orderly shutdown.
pub struct TelemetryGuard(Option<SdkTracerProvider>);

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct W3cTraceContext {
    pub trace_parent: Option<String>,
    pub trace_state: Option<String>,
}

/// Serializes the current span into a W3C carrier for durable storage or HTTP propagation.
pub(crate) fn current_trace_context() -> W3cTraceContext {
    let mut carrier = HashMap::new();
    opentelemetry::global::get_text_map_propagator(|propagator| {
        propagator.inject_context(&tracing::Span::current().context(), &mut carrier);
    });
    W3cTraceContext {
        trace_parent: carrier.remove("traceparent"),
        trace_state: carrier.remove("tracestate"),
    }
}

/// Attaches a persisted W3C context as the parent of a newly-created worker span.
///
/// A missing trace parent is normal for internally admitted operations. A malformed
/// persisted parent is rejected so the caller can emit an explicit diagnostic.
pub(crate) fn attach_durable_trace_parent(
    span: &tracing::Span,
    trace_parent: Option<&str>,
    trace_state: Option<&str>,
) -> Result<bool, ()> {
    let Some(trace_parent) = trace_parent else {
        return Ok(false);
    };
    let mut carrier = HashMap::from([("traceparent".to_owned(), trace_parent.to_owned())]);
    if let Some(trace_state) = trace_state {
        carrier.insert("tracestate".to_owned(), trace_state.to_owned());
    }
    let parent: Context =
        opentelemetry::global::get_text_map_propagator(|propagator| propagator.extract(&carrier));
    if !parent.span().span_context().is_valid() {
        return Err(());
    }
    span.set_parent(parent).map_err(|_| ())?;
    Ok(true)
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.0.take()
            && provider.shutdown().is_err()
        {
            // The tracing subscriber may already be shutting down. Never print
            // the exporter error: it can contain a credential-bearing endpoint.
            eprintln!("OpenTelemetry shutdown failed (error_class=telemetry_shutdown)");
        }
    }
}

pub fn init(service_name: &'static str) -> anyhow::Result<TelemetryGuard> {
    opentelemetry::global::set_text_map_propagator(
        opentelemetry_sdk::propagation::TraceContextPropagator::new(),
    );
    let endpoint_configured = [
        "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
        "OTEL_EXPORTER_OTLP_ENDPOINT",
    ]
    .iter()
    .any(|name| std::env::var(name).is_ok_and(|value| !value.trim().is_empty()));
    let provider = if endpoint_configured {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()?;
        Some(
            SdkTracerProvider::builder()
                .with_resource(Resource::builder().with_service_name(service_name).build())
                .with_batch_exporter(exporter)
                .build(),
        )
    } else {
        None
    };
    let otel_layer = provider.as_ref().map(|provider| {
        tracing_opentelemetry::layer()
            .with_tracer(provider.tracer(service_name))
            .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                metadata.is_span()
            }))
    });
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().json())
        .with(otel_layer)
        .try_init()?;
    Ok(TelemetryGuard(provider))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use opentelemetry::trace::{TraceContextExt as _, TracerProvider as _};
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_opentelemetry::OpenTelemetrySpanExt as _;
    use tracing_subscriber::layer::SubscriberExt as _;

    use super::{attach_durable_trace_parent, current_trace_context};

    #[test]
    fn exporter_is_opt_in_and_never_defaults_to_localhost() {
        let source = include_str!("telemetry.rs");
        assert!(source.contains("endpoint_configured"));
        assert!(source.contains("if endpoint_configured"));
        assert!(source.contains("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"));
    }

    #[test]
    fn durable_trace_context_round_trips_from_request_span_to_worker_parent() {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        let provider = SdkTracerProvider::builder().build();
        let subscriber = tracing_subscriber::registry().with(
            tracing_opentelemetry::layer().with_tracer(provider.tracer("durable-trace-test")),
        );

        tracing::subscriber::with_default(subscriber, || {
            let inbound = HashMap::from([
                (
                    "traceparent".to_owned(),
                    "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".to_owned(),
                ),
                ("tracestate".to_owned(), "vendor=value".to_owned()),
            ]);
            let remote_parent = opentelemetry::global::get_text_map_propagator(|propagator| {
                propagator.extract(&inbound)
            });
            let request_span = tracing::info_span!("http_request_test");
            request_span.set_parent(remote_parent).unwrap();
            let request_context = request_span.context();
            let request_span_context = request_context.span().span_context().clone();

            let persisted = {
                let _entered = request_span.enter();
                current_trace_context()
            };
            assert_eq!(persisted.trace_state.as_deref(), Some("vendor=value"));

            let durable_parent = persisted.trace_parent.as_ref().unwrap();
            let worker_span = tracing::info_span!("durable_operation_test");
            assert_eq!(
                attach_durable_trace_parent(
                    &worker_span,
                    Some(durable_parent),
                    persisted.trace_state.as_deref(),
                ),
                Ok(true)
            );
            let worker_context = worker_span.context();
            let worker_context_span = worker_context.span();
            let worker_span_context = worker_context_span.span_context();

            assert_eq!(
                worker_span_context.trace_id(),
                request_span_context.trace_id(),
                "the worker span must continue the HTTP request trace"
            );
            assert_ne!(
                worker_span_context.span_id(),
                request_span_context.span_id(),
                "the worker must be a child span, not a reuse of the request span"
            );
        });
        provider.shutdown().unwrap();
    }

    #[test]
    fn malformed_durable_trace_parent_is_rejected() {
        let span = tracing::info_span!("durable_operation_test");
        assert_eq!(
            attach_durable_trace_parent(&span, Some("not-a-traceparent"), None),
            Err(())
        );
    }
}
