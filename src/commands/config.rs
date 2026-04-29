use crate::errors::NyxResult;
use crate::utils::config::{AnalysisRulesConfig, CapName, Config, ConfigLabelRule, RuleKind};
use console::style;
use std::fs;
use std::path::Path;

/// Show the configuration as TOML.
///
/// By default emits only the values that differ from `Config::default()`,
/// which answers the common question "what's actually customized here?"
/// without burying the user under hundreds of lines of defaults.  Pass
/// `all=true` to emit the full effective configuration (useful when piping
/// into a starter `nyx.local` file).
///
/// Section headers are coloured cyan and keys dimmed when stdout is a
/// terminal.  `console::style` automatically strips ANSI when output is
/// redirected to a file or another command, so the bytes a pipe sees are
/// always plain valid TOML.
pub fn show(config: &Config, all: bool) -> NyxResult<()> {
    let toml_str = if all {
        toml::to_string_pretty(config).map_err(|e| format!("Failed to serialize config: {e}"))?
    } else {
        diff_from_defaults_toml(config)?
    };

    let trimmed = toml_str.trim();
    let override_count = count_top_level_keys(trimmed);

    if !all {
        let header = if override_count == 0 {
            "# No overrides, using built-in defaults. Run `nyx config show --all` for the full effective config.".to_string()
        } else {
            format!(
                "# {} override(s) shown. Run `nyx config show --all` for the full effective config.",
                override_count
            )
        };
        println!("{}", style(header).dim());
    }

    if trimmed.is_empty() {
        return Ok(());
    }

    print_toml_with_highlights(&toml_str);
    Ok(())
}

/// Render TOML with section headers in cyan/bold and key names dimmed.
/// `console::style` strips ANSI automatically when stdout is not a TTY,
/// so piped output remains valid TOML.
fn print_toml_with_highlights(toml_str: &str) {
    for line in toml_str.lines() {
        let trimmed = line.trim_start();
        if (trimmed.starts_with('[') && trimmed.contains(']')) || trimmed.starts_with("[[") {
            println!("{}", style(line).cyan().bold());
            continue;
        }
        // key = value lines (but not `[xxx]`).  Split on the first `=`
        // that isn't inside a quoted string — TOML keys don't contain
        // `=` outside quotes, so a leading-segment split is safe enough
        // for the common case.  Continuation lines from multi-line
        // arrays/strings won't have `=` and fall through to plain.
        if let Some(eq_idx) = find_top_level_equals(line) {
            let (key_part, rest) = line.split_at(eq_idx);
            println!("{}{}", style(key_part).dim(), rest);
            continue;
        }
        println!("{line}");
    }
}

/// Locate the index of the first `=` outside any quoted segment in a
/// TOML key/value line.  Returns `None` for non-assignment lines.
fn find_top_level_equals(line: &str) -> Option<usize> {
    let mut in_string = false;
    let mut quote_char = '"';
    for (idx, ch) in line.char_indices() {
        if in_string {
            if ch == quote_char {
                in_string = false;
            }
        } else {
            match ch {
                '#' => return None,
                '"' | '\'' => {
                    in_string = true;
                    quote_char = ch;
                }
                '=' => return Some(idx),
                _ => {}
            }
        }
    }
    None
}

/// Diff the user's effective config against `Config::default()` and
/// render the surviving subset as pretty TOML.  Returns the empty
/// string when nothing differs.
fn diff_from_defaults_toml(config: &Config) -> NyxResult<String> {
    // Normalize both sides through the same merge pipeline.  When a
    // user has a `nyx.local` the runtime already runs effective through
    // `merge_configs`; when there's no user file it doesn't, so
    // exclusion arrays stay in their original order and won't compare
    // equal to the merged-default's sorted form.  Re-merging both
    // sides is idempotent for the already-merged case and brings the
    // no-user-file case into the same shape, so the diff is stable.
    let normalized_effective =
        crate::utils::config::merge_configs(Config::default(), config.clone());
    let normalized_default =
        crate::utils::config::merge_configs(Config::default(), Config::default());

    let effective: toml::Value = toml::Value::try_from(&normalized_effective)
        .map_err(|e| format!("Failed to serialize config: {e}"))?;
    let defaults: toml::Value = toml::Value::try_from(&normalized_default)
        .map_err(|e| format!("Failed to serialize default config: {e}"))?;

    let pruned = prune_matching(&effective, &defaults)
        .unwrap_or(toml::Value::Table(toml::value::Table::new()));

    let table = match pruned {
        toml::Value::Table(t) => t,
        _ => toml::value::Table::new(),
    };

    if table.is_empty() {
        return Ok(String::new());
    }

    toml::to_string_pretty(&table)
        .map_err(|e| format!("Failed to serialize diff config: {e}").into())
}

/// Recursively drop entries from `effective` that match `defaults`.
/// Returns `None` when the resulting subtree is empty (so the caller
/// can drop the key entirely).  Non-table values compare by equality;
/// arrays are kept whole when they differ at all (TOML lacks a clean
/// per-element diff representation).
fn prune_matching(effective: &toml::Value, defaults: &toml::Value) -> Option<toml::Value> {
    match (effective, defaults) {
        (toml::Value::Table(eff), toml::Value::Table(def)) => {
            let mut out = toml::value::Table::new();
            for (k, v) in eff {
                match def.get(k) {
                    Some(dv) => {
                        if let Some(diff) = prune_matching(v, dv) {
                            out.insert(k.clone(), diff);
                        }
                    }
                    None => {
                        // Key absent in defaults — keep entirely.
                        out.insert(k.clone(), v.clone());
                    }
                }
            }
            if out.is_empty() {
                None
            } else {
                Some(toml::Value::Table(out))
            }
        }
        // Identical leaf — drop.
        _ if effective == defaults => None,
        // Differing leaf or shape change — keep the effective value.
        _ => Some(effective.clone()),
    }
}

/// Count individual `key = value` overrides in a TOML string,
/// ignoring section headers, comments, blank lines, and continuation
/// lines from multi-line arrays/tables.  Drives the
/// `# N override(s) shown` banner.
fn count_top_level_keys(toml_str: &str) -> usize {
    let mut count = 0;
    let mut in_multiline = false;
    for line in toml_str.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            // Section header — not an override on its own.  Reset
            // any stuck multi-line state defensively.
            in_multiline = false;
            continue;
        }
        if in_multiline {
            // Inside a multi-line array/inline table — closing bracket
            // ends it, intermediate lines don't count.
            if trimmed.starts_with(']') || trimmed.starts_with('}') {
                in_multiline = false;
            }
            continue;
        }
        if find_top_level_equals(line).is_some() {
            count += 1;
            // A `key = [` or `key = {` opens a multi-line block whose
            // continuation lines should not be counted as new keys.
            let after_eq = line.split_once('=').map(|x| x.1.trim_start()).unwrap_or("");
            if (after_eq.starts_with('[') && !after_eq.contains(']'))
                || (after_eq.starts_with('{') && !after_eq.contains('}'))
            {
                in_multiline = true;
            }
        }
    }
    count
}

/// Print the configuration directory path.
pub fn path(config_dir: &Path) -> NyxResult<()> {
    println!("{}", config_dir.display());
    Ok(())
}

/// Add a label rule to `nyx.local`.
pub fn add_rule(
    config_dir: &Path,
    lang: &str,
    matcher: &str,
    kind: &str,
    cap: &str,
) -> NyxResult<()> {
    let rule_kind: RuleKind = kind
        .parse()
        .map_err(|e: String| crate::errors::NyxError::Msg(e))?;
    let cap_name: CapName = cap
        .parse()
        .map_err(|e: String| crate::errors::NyxError::Msg(e))?;

    let local_path = config_dir.join("nyx.local");
    let mut config: Config = if local_path.exists() {
        let content = fs::read_to_string(&local_path)?;
        toml::from_str(&content)?
    } else {
        Config::default()
    };

    let lang_cfg = config
        .analysis
        .languages
        .entry(lang.to_string())
        .or_default();

    let new_rule = ConfigLabelRule {
        matchers: vec![matcher.to_string()],
        kind: rule_kind,
        cap: cap_name,
        case_sensitive: false,
    };

    // Dedup
    if !lang_cfg.rules.contains(&new_rule) {
        lang_cfg.rules.push(new_rule);
    }

    save_local_config(&local_path, &config)?;

    println!(
        "{}: Added {} rule for `{}` ({}) in {}",
        style("ok").green().bold(),
        kind,
        matcher,
        cap,
        lang
    );
    Ok(())
}

/// Add a terminator to `nyx.local`.
pub fn add_terminator(config_dir: &Path, lang: &str, name: &str) -> NyxResult<()> {
    let local_path = config_dir.join("nyx.local");
    let mut config: Config = if local_path.exists() {
        let content = fs::read_to_string(&local_path)?;
        toml::from_str(&content)?
    } else {
        Config::default()
    };

    let lang_cfg = config
        .analysis
        .languages
        .entry(lang.to_string())
        .or_default();

    if !lang_cfg.terminators.contains(&name.to_string()) {
        lang_cfg.terminators.push(name.to_string());
    }

    save_local_config(&local_path, &config)?;

    println!(
        "{}: Added terminator `{}` for {}",
        style("ok").green().bold(),
        name,
        lang
    );
    Ok(())
}

/// Write only the non-default portions to nyx.local.
pub(crate) fn save_local_config(path: &Path, config: &Config) -> NyxResult<()> {
    // Write analysis + profiles + server settings to nyx.local.
    let mut local = Config {
        analysis: config.analysis.clone(),
        profiles: config.profiles.clone(),
        server: config.server.clone(),
        ..Config::default()
    };

    // Strip empty language entries
    local.analysis.languages.retain(|_, v| {
        !v.rules.is_empty() || !v.terminators.is_empty() || !v.event_handlers.is_empty()
    });

    // If no analysis rules and no disabled rules, clear the analysis section
    if local.analysis.languages.is_empty() && local.analysis.disabled_rules.is_empty() {
        local.analysis = AnalysisRulesConfig::default();
    }

    let toml_str =
        toml::to_string_pretty(&local).map_err(|e| format!("Failed to serialize config: {e}"))?;
    fs::write(path, toml_str)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_rule_writes_valid_toml() {
        let dir = tempfile::tempdir().unwrap();
        add_rule(
            dir.path(),
            "javascript",
            "escapeHtml",
            "sanitizer",
            "html_escape",
        )
        .unwrap();

        let content = fs::read_to_string(dir.path().join("nyx.local")).unwrap();
        let config: Config = toml::from_str(&content).unwrap();
        let js = config.analysis.languages.get("javascript").unwrap();
        assert_eq!(js.rules.len(), 1);
        assert_eq!(js.rules[0].matchers, vec!["escapeHtml"]);
        assert_eq!(js.rules[0].kind, RuleKind::Sanitizer);
        assert_eq!(js.rules[0].cap, CapName::HtmlEscape);
    }

    #[test]
    fn add_rule_deduplicates() {
        let dir = tempfile::tempdir().unwrap();
        add_rule(
            dir.path(),
            "javascript",
            "escapeHtml",
            "sanitizer",
            "html_escape",
        )
        .unwrap();
        add_rule(
            dir.path(),
            "javascript",
            "escapeHtml",
            "sanitizer",
            "html_escape",
        )
        .unwrap();

        let content = fs::read_to_string(dir.path().join("nyx.local")).unwrap();
        let config: Config = toml::from_str(&content).unwrap();
        let js = config.analysis.languages.get("javascript").unwrap();
        assert_eq!(js.rules.len(), 1);
    }

    #[test]
    fn add_terminator_works() {
        let dir = tempfile::tempdir().unwrap();
        add_terminator(dir.path(), "javascript", "process.exit").unwrap();

        let content = fs::read_to_string(dir.path().join("nyx.local")).unwrap();
        let config: Config = toml::from_str(&content).unwrap();
        let js = config.analysis.languages.get("javascript").unwrap();
        assert_eq!(js.terminators, vec!["process.exit"]);
    }

    #[test]
    fn add_rule_rejects_invalid_kind() {
        let dir = tempfile::tempdir().unwrap();
        let result = add_rule(dir.path(), "javascript", "foo", "invalid_kind", "all");
        assert!(result.is_err());
    }

    #[test]
    fn add_rule_rejects_invalid_cap() {
        let dir = tempfile::tempdir().unwrap();
        let result = add_rule(dir.path(), "javascript", "foo", "sanitizer", "invalid_cap");
        assert!(result.is_err());
    }
}
