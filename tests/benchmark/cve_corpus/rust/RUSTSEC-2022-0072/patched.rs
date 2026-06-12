// Nyx CVE benchmark fixture (patched counterpart).
//
// CVE:      RUSTSEC-2022-0072 (GHSA-5wvv-q5fv-2388; no CVE id assigned)
// Project:  hyper-staticfile (stephank/hyper-staticfile), fix in 0.9.4
// License:  MIT
// Advisory: https://rustsec.org/advisories/RUSTSEC-2022-0072.html
// Patched:  f12cadc6666c6f555d29725f5bc45da2103f24ea
//           src/resolve.rs:155-189
//
// Patched variant: the directory-redirect target is rebuilt from the
// *sanitized* filesystem path (`RequestedPath::resolve(request_path).sanitized`),
// not the raw request path. `RequestedPath::resolve` normalises away `..`
// traversal and the leading-empty component that makes `//host` scheme-relative,
// and the target is reassembled component-by-component, so the `Location`
// value can never become a scheme-relative redirect.
//
// Patched-fix simplification: `RequestedPath::resolve` is stubbed to a
// `PathBuf::from` so the file parses standalone; upstream it performs the real
// traversal-stripping sanitisation. The load-bearing decision — building the
// redirect from the sanitized path's components rather than the raw request
// path — is preserved verbatim. Same single-file scaffolding as the vulnerable
// fixture (env::var source, inlined builder).
use std::env;
use std::path::PathBuf;

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
struct RequestedPath {
    sanitized: PathBuf,
    is_dir_request: bool,
}
impl RequestedPath {
    fn resolve(request_path: &str) -> RequestedPath {
        RequestedPath {
            sanitized: PathBuf::from(request_path),
            is_dir_request: false,
        }
    }
}

fn build_directory_redirect() {
    let request_path = env::var("REQUEST_PATH").unwrap();

    // Sanitize input path.
    let RequestedPath {
        sanitized: mut path,
        is_dir_request: _,
    } = RequestedPath::resolve(&request_path);

    // Build the redirect path. On Windows, we can't just append the entire
    // path, because it contains Windows path separators. Instead, append each
    // component separately.
    let mut target = String::with_capacity(path.as_os_str().len() + 2);
    target.push('/');
    for component in path.components() {
        target.push_str(&component.as_os_str().to_string_lossy());
        target.push('/');
    }

    HttpResponseBuilder::new()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, target)
        .body(Body::Empty);
}
