// Synthetic safe counterpart to chained_builder_location.rs. The same
// chained-builder Location sink, but the URL is routed through
// `ensure_relative_url` (a recognised OPEN_REDIRECT sanitiser) before the
// sink. Precision guard: the chained-builder middle-gate rebinding must NOT
// produce an open-redirect finding when the payload is sanitised.
use std::env;

fn ensure_relative_url(raw: &str) -> String {
    format!("/{}", raw.trim_start_matches('/'))
}

struct Resp;
impl Resp {
    fn new() -> Self {
        Resp
    }
    fn status(self, _c: u16) -> Self {
        self
    }
    fn header(self, _n: &str, _v: String) -> Self {
        self
    }
    fn finish(self) {}
}

fn handler() {
    let next = env::var("next").unwrap();
    let safe = ensure_relative_url(&next);
    Resp::new().status(302).header("Location", safe).finish();
}
