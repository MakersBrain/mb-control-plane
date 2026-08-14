-- Runtime roles may enqueue operations, but they must not gain direct access to
-- data-subject processing holds merely so this enforcement trigger can inspect
-- them. The function contains no dynamic SQL and uses a fixed trusted search
-- path, so SECURITY DEFINER preserves the privacy boundary safely.
alter function control.enforce_subject_processing_hold() security definer;
alter function control.enforce_subject_processing_hold()
    set search_path = pg_catalog, control;
