// Nyx CVE benchmark fixture.
//
// CVE:        RUSTSEC-2022-0072 (GHSA-5wvv-q5fv-2388; no CVE id assigned)
// Project:    hyper-staticfile (stephank/hyper-staticfile)
// License:    MIT
// Advisory:   https://rustsec.org/advisories/RUSTSEC-2022-0072.html
// Vulnerable: 2ff8d89e6d30dfbc753cd681e67013ea2daa3a8e
//             src/response_builder.rs:94-106
//
// hyper-staticfile < 0.9.4 built the directory-redirect `Location` header by
// taking the raw request path (`self.path`, set from `uri.path()`), appending
// a trailing slash, and emitting it unvalidated as the `Location` of a 301
// response. A request path beginning with `//` (e.g. `//evil.com/`) is a
// scheme-relative URL, so the browser redirects to an attacker-controlled
// host (open redirect / phishing pivot). Fixed in 0.9.4 by rebuilding the
// redirect target from the sanitized filesystem path in resolve.rs.
//
// Trims: the ResolveResult enum and its other match arms (MethodNotMatched /
// NotFound / PermissionDenied / Found), the FileResponseBuilder, and the
// request/request_parts/request_uri/path/query setters. The request path
// source is modeled via env::var so the single-file harness sees the flow
// (upstream: ResponseBuilder::request_uri -> self.path(uri.path())); the
// `self.path`/`self.query` field reads are inlined to locals `path`/`query`,
// mirroring the gitoxide CVE-2024-32884 fixture's single-file convention. The
// load-bearing IsDirectory arm — target construction, trailing-slash + query
// append, and the chained `.header(LOCATION, target)` Location sink — is
// preserved verbatim.
use std::env;

mod header {
    pub const LOCATION: &str = "location";
}
struct StatusCode;
impl StatusCode {
    const MOVED_PERMANENTLY: u16 = 301;
}
enum Body {
    Empty,
}
struct HttpResponseBuilder;
impl HttpResponseBuilder {
    fn new() -> Self {
        HttpResponseBuilder
    }
    fn status(self, _s: u16) -> Self {
        self
    }
    fn header(self, _name: &str, _value: String) -> Self {
        self
    }
    fn body(self, _b: Body) {}
}

fn build_directory_redirect() {
    // Source: the raw request path (upstream `self.path`, from `uri.path()`).
    let path = env::var("REQUEST_PATH").unwrap();
    let q = env::var("REQUEST_QUERY").ok();
    let query: Option<&str> = q.as_deref();

    let mut target = path.to_owned();
    target.push('/');
    if let Some(query) = query {
        target.push('?');
        target.push_str(query);
    }

    HttpResponseBuilder::new()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, target)
        .body(Body::Empty);
}
