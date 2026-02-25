use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::Command;

// ───── Configuration from environment ─────

struct AppConfig {
    db_url: String,
    upload_dir: String,
    admin_token: String,
    log_level: String,
}

fn load_config() -> AppConfig {
    AppConfig {
        db_url: env::var("DATABASE_URL").unwrap(),
        upload_dir: env::var("UPLOAD_DIR").unwrap(),
        admin_token: env::var("ADMIN_TOKEN").expect("ADMIN_TOKEN must be set"),
        log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string()),
    }
}

// ───── Request handling ─────

struct Request {
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

struct Response {
    status: u16,
    body: String,
}

/// POST /admin/run-migration
/// Reads a migration script name from the environment and executes it.
/// VULN: env var flows directly into Command without sanitization.
fn handle_migration() -> Response {
    let script = env::var("MIGRATION_SCRIPT").unwrap();
    let output = Command::new("bash")
        .arg("-c")
        .arg(&script)
        .output()
        .expect("migration failed");

    Response {
        status: 200,
        body: String::from_utf8_lossy(&output.stdout).to_string(),
    }
}

/// POST /admin/deploy
/// Reads deployment target from config file (which is a source),
/// then shells out.
/// VULN: file contents flow into Command.
fn handle_deploy() -> Response {
    let manifest = fs::read_to_string("/etc/deploy/manifest.toml").unwrap();
    let target = manifest.lines().next().unwrap();
    let status = Command::new("rsync")
        .arg("-avz")
        .arg("./build/")
        .arg(target)
        .status()
        .unwrap();

    Response {
        status: if status.success() { 200 } else { 500 },
        body: format!("deploy exited with {}", status),
    }
}

/// GET /admin/export
/// Constructs a shell command from an env-var driven path.
/// VULN: env var flows into Command::arg.
fn handle_export() -> Response {
    let config = load_config();
    let dump_cmd = format!("pg_dump {}", config.db_url);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&dump_cmd)
        .output()
        .unwrap();

    let dump_path = format!("{}/export.sql", config.upload_dir);
    fs::write(&dump_path, &output.stdout).unwrap();

    Response {
        status: 200,
        body: format!("Exported to {}", dump_path),
    }
}

/// POST /admin/backup
/// SAFE: uses a hardcoded command, no taint from external input.
fn handle_backup() -> Response {
    let output = Command::new("tar")
        .arg("-czf")
        .arg("/backups/nightly.tar.gz")
        .arg("/var/data")
        .output()
        .expect("backup failed");

    Response {
        status: if output.status.success() { 200 } else { 500 },
        body: "backup complete".to_string(),
    }
}

/// POST /admin/cleanup
/// SAFE: shell_escape sanitizer applied before sink.
fn handle_cleanup() -> Response {
    let dir = env::var("CLEANUP_DIR").unwrap();
    let safe_dir = sanitize_shell(&dir);
    let output = Command::new("rm")
        .arg("-rf")
        .arg(&safe_dir)
        .output()
        .unwrap();

    Response {
        status: 200,
        body: format!("cleaned up, exit={}", output.status),
    }
}

fn sanitize_shell(input: &str) -> String {
    input.replace(['&', ';', '|', '$', '`', '\\', '"', '\''], "")
}

// ───── Unsafe FFI bridge ─────

/// Re-encodes a buffer from an external C library.
/// VULN: unsafe block for FFI.
unsafe fn decode_legacy_buffer(ptr: *const u8, len: usize) -> Vec<u8> {
    std::slice::from_raw_parts(ptr, len).to_vec()
}

/// Transmutes raw byte data into a config header struct.
/// VULN: transmute is inherently dangerous, mem::zeroed is UB-prone.
fn parse_legacy_header(bytes: &[u8]) -> u64 {
    if bytes.len() < 8 {
        panic!("header too short");
    }
    unsafe { std::mem::transmute::<[u8; 8], u64>(bytes[..8].try_into().unwrap()) }
}

// ───── Utility functions with code smells ─────

fn read_pid_file(path: &str) -> u32 {
    let contents = fs::read_to_string(path).unwrap();
    contents.trim().parse::<u32>().expect("invalid pid")
}

/// TODO: implement proper logging
fn setup_logging() {
    todo!()
}

fn debug_request(req: &Request) {
    dbg!(&req.path);
    dbg!(&req.body);
}
