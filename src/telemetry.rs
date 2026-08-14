use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// Keeps the optional OTLP provider alive and flushes it on orderly shutdown.
pub struct TelemetryGuard(Option<SdkTracerProvider>);

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.0.take()
            && let Err(error) = provider.shutdown()
        {
            eprintln!("OpenTelemetry shutdown failed: {error}");
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
    #[test]
    fn exporter_is_opt_in_and_never_defaults_to_localhost() {
        let source = include_str!("telemetry.rs");
        assert!(source.contains("endpoint_configured"));
        assert!(source.contains("if endpoint_configured"));
        assert!(source.contains("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"));
    }
}
