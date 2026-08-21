-- Release volumes are workspace-prefixed in developer stacks while existing
-- deployments retain the historical mb-ext-* form.
alter table control.runtime_release_slots
  drop constraint runtime_release_slots_extension_volume_check,
  add constraint runtime_release_slots_extension_volume_check
    check (extension_volume ~ '^mb-(control-|dev[1-4]-)?ext-[a-f0-9]{16}-[a-f0-9]{16}$');

alter table control.extension_volume_preparations
  drop constraint extension_volume_preparations_volume_name_check,
  add constraint extension_volume_preparations_volume_name_check
    check (volume_name ~ '^mb-(control-|dev[1-4]-)?ext-[a-f0-9]{16}-[a-f0-9]{16}$');
