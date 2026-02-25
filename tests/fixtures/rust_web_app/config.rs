use std::env;
use std::fs;

/// Application configuration loaded from environment variables and config files.
/// Realistic pattern: env vars parsed at startup, propagated through the app.

pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub name: String,
}

pub struct ServerConfig {
    pub listen_addr: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub session_secret: String,
}

pub struct Config {
    pub db: DatabaseConfig,
    pub server: ServerConfig,
}

impl Config {
    /// Load config from environment.
    /// Multiple env::var calls, each introducing a source.
    pub fn from_env() -> Config {
        Config {
            db: DatabaseConfig {
                host: env::var("DB_HOST").unwrap_or_else(|_| "localhost".into()),
                port: env::var("DB_PORT")
                    .unwrap_or_else(|_| "5432".into())
                    .parse()
                    .expect("DB_PORT must be a number"),
                user: env::var("DB_USER").unwrap(),
                password: env::var("DB_PASSWORD").unwrap(),
                name: env::var("DB_NAME").unwrap(),
            },
            server: ServerConfig {
                listen_addr: env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into()),
                tls_cert_path: env::var("TLS_CERT").unwrap_or_default(),
                tls_key_path: env::var("TLS_KEY").unwrap_or_default(),
                session_secret: env::var("SESSION_SECRET")
                    .expect("SESSION_SECRET is required for cookie signing"),
            },
        }
    }

    /// Alternative: load from a TOML file.
    /// fs::read_to_string is a file source.
    pub fn from_file(path: &str) -> Config {
        let raw = fs::read_to_string(path).unwrap();
        // In real code this would be toml::from_str(&raw) but we simulate
        // the pattern: file contents flowing into the app.
        let _parsed = raw.lines().count();
        Config::from_env() // fallback to env for now
    }
}

/// Build a connection string from config.
/// The password from env flows into a string that could be logged or misused.
pub fn connection_string(cfg: &Config) -> String {
    format!(
        "postgres://{}:{}@{}:{}/{}",
        cfg.db.user, cfg.db.password, cfg.db.host, cfg.db.port, cfg.db.name
    )
}
