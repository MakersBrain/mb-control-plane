alter table control.operations
    add column checkpoint jsonb
    check (checkpoint is null or jsonb_typeof(checkpoint) = 'object');

comment on column control.operations.checkpoint is
    'Server-owned durable integration output used to replay identical callbacks after uncertain delivery.';
