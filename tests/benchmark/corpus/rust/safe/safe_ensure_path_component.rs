// Safe: the cache-key path component is validated by a Result-returning
// path-safety guard (`ensure_safe_path_component(x)?`) before it is joined
// into the cache path, so the tainted build string cannot escape the cache
// root. Pins the CVE-2026-53956 confiner: a `..`/separator-rejecting
// `Result` guard whose name matches the path-safety-validator grammar clears
// Cap::FILE_IO on its argument.
use std::env;
use std::path::PathBuf;

#[derive(Debug)]
pub struct InvalidPathComponentError {
    pub value: String,
}
impl std::fmt::Display for InvalidPathComponentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsafe path component: {}", self.value)
    }
}
impl std::error::Error for InvalidPathComponentError {}

pub fn ensure_safe_path_component(component: &str) -> Result<(), InvalidPathComponentError> {
    let is_unsafe = component == "."
        || component == ".."
        || component
            .chars()
            .any(|c| matches!(c, '/' | '\\' | ':' | '\0') || c.is_control());
    if is_unsafe {
        Err(InvalidPathComponentError {
            value: component.to_string(),
        })
    } else {
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cache_root = PathBuf::from("/tmp/pkgs");
    let build = env::var("PKG_BUILD").unwrap_or_default();
    let segment = format!("demo-1.0-{}", build);
    ensure_safe_path_component(&segment)?;
    let cache_path = cache_root.join(segment);
    std::fs::write(cache_path.join("payload"), b"x")?;
    Ok(())
}
