// Recall guard: the path-safety validator `ensure_safe_path_component` is
// DEFINED but never called on the flow, so the tainted build string still
// reaches fs::write and the path-traversal flow must still fire. Pins that
// merely defining a path-safety-named `Result` guard does not suppress an
// unguarded path (the confinement is applied only at an actual guarded call
// site — CVE-2026-53956).
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
    // NB: ensure_safe_path_component is never called on `segment`.
    let cache_path = cache_root.join(segment);
    std::fs::write(cache_path.join("payload"), b"x")?;
    Ok(())
}
