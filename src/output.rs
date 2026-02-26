use crate::commands::scan::Diag;
use crate::patterns::{self, Severity};
use once_cell::sync::Lazy;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;

/// Lazily-built global map: pattern ID → description from all language registries.
static PATTERN_DESCRIPTIONS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut map = HashMap::new();
    for lang in &[
        "rust",
        "c",
        "cpp",
        "java",
        "go",
        "php",
        "python",
        "ruby",
        "javascript",
        "typescript",
    ] {
        for p in patterns::load(lang) {
            map.entry(p.id).or_insert(p.description);
        }
    }
    map
});

/// CFG rule descriptions for rules not in the pattern registry.
fn cfg_rule_description(id: &str) -> Option<&'static str> {
    match id {
        "cfg-unguarded-sink" => Some("Dangerous sink reachable without prior guard or sanitizer"),
        "cfg-unreachable-sink" => Some("Sink in unreachable code"),
        "cfg-auth-gap" => Some("Entry-point handler reaches sink without authentication check"),
        "cfg-error-fallthrough" => {
            Some("Error check does not terminate; dangerous call follows on error path")
        }
        "cfg-resource-leak" => Some("Resource acquired but not released on all exit paths"),
        "cfg-lock-not-released" => Some("Lock acquired but not released on all exit paths"),
        "state-use-after-close" => Some("Variable used after its resource handle was closed"),
        "state-double-close" => Some("Resource handle closed more than once"),
        "state-resource-leak" => Some("Resource acquired but never closed"),
        "state-resource-leak-possible" => Some("Resource may not be closed on all paths"),
        "state-unauthed-access" => Some("Sensitive operation reached without authentication"),
        _ => None,
    }
}

/// Look up a human-readable description for any rule ID.
fn rule_description(id: &str) -> &str {
    // Strip taint-specific suffix for lookup (e.g. "taint-unsanitised-flow:foo.rs:42" → base)
    let base_id = if id.starts_with("taint-") {
        "taint-unsanitised-flow"
    } else {
        id
    };

    if let Some(desc) = PATTERN_DESCRIPTIONS.get(base_id) {
        return desc;
    }
    if let Some(desc) = cfg_rule_description(base_id) {
        return desc;
    }
    if base_id == "taint-unsanitised-flow" {
        return "Unsanitised data flows from source to sink";
    }
    id
}

fn severity_to_level(sev: Severity) -> &'static str {
    match sev {
        Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

/// Build a SARIF 2.1.0 JSON value from a list of diagnostics.
pub fn build_sarif(diags: &[Diag], scan_root: &Path) -> Value {
    // Deduplicate rule IDs and build rules array.
    let mut rule_ids: Vec<String> = Vec::new();
    let mut rule_index_map: HashMap<String, usize> = HashMap::new();

    for d in diags {
        let base = if d.id.starts_with("taint-") {
            "taint-unsanitised-flow".to_string()
        } else {
            d.id.clone()
        };
        if !rule_index_map.contains_key(&base) {
            let idx = rule_ids.len();
            rule_index_map.insert(base.clone(), idx);
            rule_ids.push(base);
        }
    }

    let rules: Vec<Value> = rule_ids
        .iter()
        .map(|id| {
            json!({
                "id": id,
                "shortDescription": { "text": rule_description(id) },
            })
        })
        .collect();

    let results: Vec<Value> = diags
        .iter()
        .map(|d| {
            let base = if d.id.starts_with("taint-") {
                "taint-unsanitised-flow"
            } else {
                &d.id
            };
            let rule_index = rule_index_map[base];

            // Make path relative to scan root if possible
            let uri = Path::new(&d.path)
                .strip_prefix(scan_root)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| d.path.clone());

            // Prefer the per-finding message (e.g. from state analysis) over the generic rule description.
            let msg_text = d
                .message
                .as_deref()
                .unwrap_or_else(|| rule_description(base));

            let mut result = json!({
                "ruleId": base,
                "ruleIndex": rule_index,
                "level": severity_to_level(d.severity),
                "message": { "text": msg_text },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": {
                            "startLine": d.line,
                            "startColumn": d.col
                        }
                    }
                }]
            });

            // Add confidence to properties if set
            if let Some(conf) = d.confidence {
                result["properties"] = json!({
                    "confidence": conf.to_string(),
                });
            }

            result
        })
        .collect();

    json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "nyx",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": env!("CARGO_PKG_HOMEPAGE"),
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}
