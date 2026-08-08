create table control.usage_reservations (
    operation_id uuid primary key references control.operations(id) on delete restrict,
    workshop_id uuid not null references control.workshops(id) on delete restrict,
    metric text not null check (metric in ('azure_invoice_pages')),
    quantity bigint not null check (quantity > 0),
    created_at timestamptz not null default now()
);

create table control.provider_rate_limits (
    provider text primary key,
    next_allowed_at timestamptz not null,
    updated_at timestamptz not null default now()
);
