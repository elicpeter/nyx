//! Triage sync: read/write `.nyx/triage.json` in the project root.
//!
//! This file is designed to be committed to version control so that triage
//! decisions travel with the code and are shared across team members.
//!
//! The file uses **portable fingerprints**, computed with paths relative to the
//! project root, so they match across machines regardless of where the repo is
//! checked out.

use crate::commands::scan::Diag;
use crate::database::index::Indexer;
use crate::server::models::compute_portable_fingerprint;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};

const MAX_TRIAGE_FILE_BYTES: u64 = 1024 * 1024;

/// On-disk format for `.nyx/triage.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageFile {
    /// Schema version for forward compatibility.
    #[serde(default = "default_version")]
    pub version: u32,
    /// Per-finding triage decisions keyed by portable fingerprint.
    #[serde(default)]
    pub decisions: Vec<TriageDecision>,
    /// Pattern-based suppression rules.
    #[serde(default)]
    pub suppression_rules: Vec<TriageSuppressionRule>,
}

fn default_version() -> u32 {
    1
}

/// A single triage decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageDecision {
    /// Portable fingerprint (blake3 of rule_id + relative_path + snippets).
    pub fingerprint: String,
    /// Triage state: open, investigating, false_positive, accepted_risk, suppressed, fixed.
    pub state: String,
    /// Optional note explaining the decision.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// Rule ID for human readability (not used for matching).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rule_id: String,
    /// Relative file path for human readability (not used for matching).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
}

/// A pattern suppression rule in the sync file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageSuppressionRule {
    /// "rule", "file", or "rule_in_file".
    pub by: String,
    /// The pattern value.
    pub value: String,
    /// Target state (usually "suppressed").
    #[serde(default = "default_suppressed")]
    pub state: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

fn default_suppressed() -> String {
    "suppressed".to_string()
}

/// Path to the triage sync file for a given scan root.
pub fn triage_file_path(scan_root: &Path) -> Result<PathBuf, String> {
    let root = canonical_scan_root(scan_root)?;
    Ok(triage_file_path_for_root(&root))
}

fn canonical_scan_root(scan_root: &Path) -> Result<PathBuf, String> {
    let canonical_root = scan_root
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize scan root: {e}"))?;
    let metadata =
        std::fs::metadata(&canonical_root).map_err(|e| format!("failed to stat scan root: {e}"))?;
    if !metadata.is_dir() {
        return Err("scan root is not a directory".to_string());
    }
    Ok(canonical_root)
}

fn triage_file_path_for_root(root: &Path) -> PathBuf {
    root.join(".nyx").join("triage.json")
}

fn validate_existing_path_within_root(path: &Path, root: &Path) -> Result<(), String> {
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("failed to canonicalize triage file path: {e}"))?;
    if !canonical.starts_with(root) {
        return Err("triage file path escapes scan root".to_string());
    }

    let metadata =
        std::fs::metadata(&canonical).map_err(|e| format!("failed to stat triage file: {e}"))?;
    if !metadata.is_file() {
        return Err("triage file path is not a regular file".to_string());
    }

    Ok(())
}

/// Compute and validate the triage file path for a given scan root.
fn validated_triage_file_path(scan_root: &Path) -> Result<PathBuf, String> {
    let root = canonical_scan_root(scan_root)?;
    let path = triage_file_path_for_root(&root);

    if let Some(parent) = path.parent()
        && parent.exists()
    {
        let canonical_parent = parent
            .canonicalize()
            .map_err(|e| format!("failed to canonicalize triage directory: {e}"))?;
        if !canonical_parent.starts_with(&root) {
            return Err("triage directory escapes scan root".to_string());
        }
        let metadata = std::fs::metadata(&canonical_parent)
            .map_err(|e| format!("failed to stat triage directory: {e}"))?;
        if !metadata.is_dir() {
            return Err("triage directory is not a directory".to_string());
        }
    }

    if path.exists() {
        validate_existing_path_within_root(&path, &root)?;
    }

    Ok(path)
}

/// Load triage decisions from `.nyx/triage.json`.
pub fn load_triage_file(scan_root: &Path) -> Option<TriageFile> {
    load_triage_file_checked(scan_root).ok().flatten()
}

pub fn load_triage_file_checked(scan_root: &Path) -> Result<Option<TriageFile>, String> {
    let path = validated_triage_file_path(scan_root)?;
    if !path.exists() {
        return Ok(None);
    }

    let content = read_bounded_text_file(&path, MAX_TRIAGE_FILE_BYTES)?;
    let parsed =
        serde_json::from_str(&content).map_err(|e| format!("failed to parse triage file: {e}"))?;
    Ok(Some(parsed))
}

/// Save triage decisions to `.nyx/triage.json`.
/// Creates the `.nyx` directory if it doesn't exist.
pub fn save_triage_file(scan_root: &Path, file: &TriageFile) -> Result<(), String> {
    let path = validated_triage_file_path(scan_root)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create .nyx directory: {e}"))?;
    }
    let json = serde_json::to_string_pretty(file)
        .map_err(|e| format!("failed to serialize triage file: {e}"))?;
    std::fs::write(&path, json).map_err(|e| format!("failed to write triage file: {e}"))?;
    Ok(())
}

fn read_bounded_text_file(path: &Path, max_bytes: u64) -> Result<String, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("failed to open file: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("failed to stat file: {e}"))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "triage file exceeds {max_bytes} bytes and was rejected"
        ));
    }

    let mut reader = std::io::BufReader::new(file).take(max_bytes);
    let mut content = String::new();
    reader
        .read_to_string(&mut content)
        .map_err(|e| format!("failed to read triage file: {e}"))?;
    Ok(content)
}

/// Export current DB triage state to a `TriageFile`.
///
/// Builds portable fingerprints from the latest scan findings, then maps
/// DB triage states (keyed by local fingerprint) onto portable fingerprints.
pub fn export_triage(
    pool: &Pool<SqliteConnectionManager>,
    findings: &[Diag],
    scan_root: &Path,
) -> Result<TriageFile, String> {
    let idx = Indexer::from_pool("_triage", pool).map_err(|e| e.to_string())?;
    let triage_map = idx.get_all_triage_states().map_err(|e| e.to_string())?;
    let suppression_rules = idx.get_suppression_rules().map_err(|e| e.to_string())?;

    // Build local_fingerprint → portable_fingerprint + metadata
    let mut decisions = Vec::new();
    for d in findings {
        let local_fp = crate::server::models::compute_fingerprint(d);
        if let Some((state, note, _)) = triage_map.get(&local_fp) {
            if state == "open" {
                continue; // Don't export default state
            }
            let portable_fp = compute_portable_fingerprint(d, scan_root);
            let rel_path = d
                .path
                .strip_prefix(scan_root.to_string_lossy().as_ref())
                .unwrap_or(&d.path)
                .trim_start_matches('/')
                .to_string();
            decisions.push(TriageDecision {
                fingerprint: portable_fp,
                state: state.clone(),
                note: note.clone(),
                rule_id: d.id.clone(),
                path: rel_path,
            });
        }
    }

    // Export suppression rules (skip fingerprint-based ones since those are local)
    let rules = suppression_rules
        .iter()
        .filter(|r| r.suppress_by != "fingerprint")
        .map(|r| TriageSuppressionRule {
            by: r.suppress_by.clone(),
            value: r.match_value.clone(),
            state: r.state.clone(),
            note: r.note.clone(),
        })
        .collect();

    Ok(TriageFile {
        version: 1,
        decisions,
        suppression_rules: rules,
    })
}

/// Import triage decisions from a `TriageFile` into the DB.
///
/// Matches portable fingerprints against current findings, then upserts
/// triage states for matches. Returns count of decisions applied.
pub fn import_triage(
    pool: &Pool<SqliteConnectionManager>,
    findings: &[Diag],
    scan_root: &Path,
    file: &TriageFile,
) -> Result<usize, String> {
    let idx = Indexer::from_pool("_triage", pool).map_err(|e| e.to_string())?;

    // Build portable_fingerprint → local_fingerprint map
    let mut portable_to_local: HashMap<String, String> = HashMap::new();
    for d in findings {
        let portable_fp = compute_portable_fingerprint(d, scan_root);
        let local_fp = crate::server::models::compute_fingerprint(d);
        portable_to_local.insert(portable_fp, local_fp);
    }

    let mut applied = 0;

    // Import decisions
    for decision in &file.decisions {
        if let Some(local_fp) = portable_to_local.get(&decision.fingerprint) {
            let _ = idx.set_triage_state(local_fp, &decision.state, &decision.note, "import");
            applied += 1;
        }
    }

    // Import suppression rules
    for rule in &file.suppression_rules {
        let _ = idx.add_suppression_rule(&rule.by, &rule.value, &rule.state, &rule.note);
    }

    Ok(applied)
}

/// Sync: load `.nyx/triage.json` if it exists and import into DB.
/// Called on server startup and after scan completion.
#[allow(dead_code)]
pub fn sync_from_file(
    pool: &Pool<SqliteConnectionManager>,
    findings: &[Diag],
    scan_root: &Path,
) -> Option<usize> {
    let file = load_triage_file(scan_root)?;
    import_triage(pool, findings, scan_root, &file).ok()
}

/// Sync: export current DB state to `.nyx/triage.json`.
/// Called after triage state changes.
pub fn sync_to_file(
    pool: &Pool<SqliteConnectionManager>,
    findings: &[Diag],
    scan_root: &Path,
) -> Result<(), String> {
    let file = export_triage(pool, findings, scan_root)?;
    save_triage_file(scan_root, &file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_triage_files_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = triage_file_path(root.path()).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, vec![b'a'; (MAX_TRIAGE_FILE_BYTES as usize) + 1]).unwrap();

        let err = load_triage_file_checked(root.path()).unwrap_err();
        assert!(err.contains("exceeds"));
    }

    #[test]
    fn triage_file_path_uses_canonical_root() {
        let root = tempfile::tempdir().unwrap();
        let requested = root.path().join(".");

        let path = triage_file_path(&requested).unwrap();

        assert_eq!(
            path,
            root.path()
                .canonicalize()
                .unwrap()
                .join(".nyx")
                .join("triage.json")
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_triage_file_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let escaped = outside.path().join("triage.json");
        std::fs::write(
            &escaped,
            serde_json::to_string(&TriageFile {
                version: 1,
                decisions: vec![],
                suppression_rules: vec![],
            })
            .unwrap(),
        )
        .unwrap();
        symlink(outside.path(), root.path().join(".nyx")).unwrap();

        let err = load_triage_file_checked(root.path()).unwrap_err();
        assert!(err.contains("escapes scan root"));
    }

    #[cfg(unix)]
    #[test]
    fn save_triage_file_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), root.path().join(".nyx")).unwrap();

        let err = save_triage_file(
            root.path(),
            &TriageFile {
                version: 1,
                decisions: vec![],
                suppression_rules: vec![],
            },
        )
        .unwrap_err();

        assert!(err.contains("escapes scan root"));
    }
}
