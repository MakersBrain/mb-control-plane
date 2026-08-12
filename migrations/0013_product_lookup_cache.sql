create table control.product_lookup_cache (
    provider text not null,
    schema_version integer not null check (schema_version > 0),
    gtin14 text not null check (gtin14 ~ '^[0-9]{14}$'),
    outcome text not null check (outcome in ('positive', 'negative')),
    candidates jsonb not null check (jsonb_typeof(candidates) = 'array'),
    retrieved_at timestamptz not null default now(),
    expires_at timestamptz not null,
    primary key (provider, schema_version, gtin14),
    check ((outcome = 'positive' and jsonb_array_length(candidates) > 0)
        or (outcome = 'negative' and jsonb_array_length(candidates) = 0))
);

create index product_lookup_cache_expiry_idx
    on control.product_lookup_cache (expires_at);
