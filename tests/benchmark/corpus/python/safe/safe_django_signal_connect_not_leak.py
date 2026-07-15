# taiga real-repo precision shape (taiga/base/signals/cleanup_files.py,
# taiga/events/apps.py, taiga/auth/settings.py): Django signal registration.
#
# `<signal>.connect(receiver, sender=..., dispatch_uid=...)` and
# `<signal>.disconnect(...)` share the `connect` callee leaf with real DB
# connection acquires, so the resource-lifecycle model wrongly reported
# `cfg-resource-leak` ("acquires db connection but not all exit paths release
# it").  A signal registration returns None and holds no resource; `disconnect`
# is a teardown verb, not an acquire.  Must fire NO resource-leak findings.


def register(model):
    # bare receiver callable, no kwargs
    setting_changed.connect(reload_api_settings)
    # receiver + Django `sender=` kwarg
    pre_save.connect(remove_files_on_change, sender=model)
    post_delete.connect(remove_files_on_delete, sender=model)
    # receiver + `dispatch_uid=` kwarg, dotted signal path
    signals.post_save.connect(on_save_any_model, dispatch_uid="events_change")
    signals.post_delete.connect(on_delete_any_model, dispatch_uid="events_delete")


def unregister():
    # `.disconnect` must not suffix-match the `connect` acquire pattern
    cleanup_post_delete.disconnect(delete_thumbnail_files)
    signals.post_save.disconnect(dispatch_uid="events_change")
    signals.pre_save.disconnect(sender=Task, dispatch_uid="set_finished_date")
