use serde::Serialize;
use serde::de::StdError;
use std::fmt;
use std::sync::PoisonError;
use thiserror::Error;

pub type NyxResult<T, E = NyxError> = Result<T, E>;

// ─── Config validation ──────────────────────────────────────────────────────

/// A single config validation error with structured metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigError {
    pub section: String,
    pub field: String,
    pub message: String,
    pub kind: ConfigErrorKind,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}.{}] {}", self.section, self.field, self.message)
    }
}

/// Category of config validation error.
#[derive(Debug, Clone, Serialize)]
pub enum ConfigErrorKind {
    OutOfRange,
    InvalidValue,
    EmptyRequired,
    Conflict,
}

#[derive(Debug, Error)]
pub enum NyxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("SQLite error: {0}")]
    Sql(#[from] rusqlite::Error),

    #[error("tree-sitter error: {0}")]
    TreeSitter(#[from] tree_sitter::LanguageError),

    #[error("connection-pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("time error: {0}")]
    Time(#[from] std::time::SystemTimeError),

    #[error("poisoned lock: {0}")]
    Poison(String),

    #[error(transparent)]
    Other(#[from] Box<dyn StdError + Send + Sync + 'static>),

    #[error("{0}")]
    Msg(String),

    #[error("config validation failed:\n{}", .0.iter().map(|e| format!("  - {e}")).collect::<Vec<_>>().join("\n"))]
    ConfigValidation(Vec<ConfigError>),
}

impl<T> From<PoisonError<T>> for NyxError
where
    T: fmt::Debug,
{
    fn from(err: PoisonError<T>) -> Self {
        NyxError::Poison(err.to_string())
    }
}

impl From<&str> for NyxError {
    fn from(s: &str) -> Self {
        NyxError::Msg(s.to_owned())
    }
}

impl From<String> for NyxError {
    fn from(s: String) -> Self {
        NyxError::Msg(s)
    }
}

impl From<Box<dyn std::error::Error>> for NyxError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        NyxError::Msg(err.to_string())
    }
}

#[test]
fn io_conversion_retains_message() {
    let e = std::io::Error::other("boom!");
    let n: NyxError = e.into();
    assert!(matches!(n, NyxError::Io(_)));
    assert!(n.to_string().contains("boom"));
}

#[test]
fn poison_conversion_maps_correct_variant() {
    let lock = std::sync::Arc::new(std::sync::Mutex::new(()));

    {
        let lock2 = std::sync::Arc::clone(&lock);
        std::thread::spawn(move || {
            let _guard = lock2.lock().unwrap();
            panic!("intentional – poison the mutex");
        })
        .join()
        .ok();
    }

    let poison = lock.lock().unwrap_err();
    let nyx: NyxError = poison.into();

    assert!(matches!(nyx, NyxError::Poison(_)));
}

#[test]
fn simple_string_into_msg() {
    let nyx: NyxError = "plain msg".into();
    assert!(matches!(nyx, NyxError::Msg(s) if s == "plain msg"));
}
