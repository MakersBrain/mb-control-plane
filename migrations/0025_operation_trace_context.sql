-- Privacy-minimised W3C trace linkage across the durable queue boundary.
alter table control.operations
    add column trace_parent text,
    add column trace_state text,
    add constraint operation_trace_parent_format check (
        trace_parent is null or trace_parent ~ '^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'
    ),
    add constraint operation_trace_state_bounded check (
        trace_state is null or (length(trace_state) between 1 and 512 and trace_state !~ '[\r\n]')
    );

comment on column control.operations.trace_parent is
    'W3C traceparent only; never a token, subject identifier or request payload.';
comment on column control.operations.trace_state is
    'Bounded W3C tracestate supplied by the configured EEA telemetry system.';
