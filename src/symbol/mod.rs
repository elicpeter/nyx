use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported source-code languages.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lang {
    Rust,
    C,
    Cpp,
    Java,
    Go,
    Php,
    Python,
    Ruby,
    TypeScript,
    JavaScript,
}

impl Lang {
    /// Parse a language slug (as returned by `lang_for_path`) into a `Lang`.
    pub fn from_slug(s: &str) -> Option<Lang> {
        match s {
            "rust" => Some(Lang::Rust),
            "c" => Some(Lang::C),
            "cpp" => Some(Lang::Cpp),
            "java" => Some(Lang::Java),
            "go" => Some(Lang::Go),
            "php" => Some(Lang::Php),
            "python" => Some(Lang::Python),
            "ruby" => Some(Lang::Ruby),
            "typescript" | "ts" => Some(Lang::TypeScript),
            "javascript" | "js" => Some(Lang::JavaScript),
            _ => None,
        }
    }

    /// Canonical slug string for this language.
    pub fn as_str(&self) -> &'static str {
        match self {
            Lang::Rust => "rust",
            Lang::C => "c",
            Lang::Cpp => "cpp",
            Lang::Java => "java",
            Lang::Go => "go",
            Lang::Php => "php",
            Lang::Python => "python",
            Lang::Ruby => "ruby",
            Lang::TypeScript => "typescript",
            Lang::JavaScript => "javascript",
        }
    }
}

impl fmt::Display for Lang {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Uniquely identifies a function across the entire project.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuncKey {
    pub lang: Lang,
    /// Project-relative file path (e.g. `"src/lib.rs"`).
    pub namespace: String,
    pub name: String,
    pub arity: Option<usize>,
}

impl fmt::Display for FuncKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}::{}", self.lang, self.namespace, self.name)?;
        if let Some(a) = self.arity {
            write!(f, "/{a}")?;
        }
        Ok(())
    }
}

/// Strip `root` prefix from `abs_path` to produce a stable project-relative path.
///
/// Falls back to the full path if stripping fails (e.g. in tests with synthetic paths).
pub fn normalize_namespace(abs_path: &str, root: Option<&str>) -> String {
    if let Some(r) = root {
        let r = r.trim_end_matches('/');
        if let Some(rest) = abs_path.strip_prefix(r) {
            return rest.trim_start_matches('/').to_string();
        }
    }
    abs_path.to_string()
}

#[cfg(test)]
mod tests;
