use axum::extract::Path;

mod realtime {
    pub fn publish_to_group(_group_id: i64, _msg: &str) {}
}

// Positive control: a request-bound path parameter flows straight to a
// realtime publish sink without any authorization check.  Phase C's
// auth-as-taint pipeline should emit `rs.auth.missing_ownership_check.taint`
// when enabled.
pub async fn handle_publish(Path(group_id): Path<i64>) -> &'static str {
    realtime::publish_to_group(group_id, "doc_updated");
    "ok"
}
