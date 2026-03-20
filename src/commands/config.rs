use crate::errors::NyxResult;
use crate::utils::config::{AnalysisRulesConfig, Config, ConfigLabelRule};
use console::style;
use std::fs;
use std::path::Path;

/// Show the effective merged configuration as TOML.
pub fn show(config: &Config) -> NyxResult<()> {
    let toml_str =
        toml::to_string_pretty(config).map_err(|e| format!("Failed to serialize config: {e}"))?;
    println!("{toml_str}");
    Ok(())
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
    // Validate kind
    if !["source", "sanitizer", "sink"].contains(&kind) {
        return Err(
            format!("Invalid kind '{kind}'. Must be one of: source, sanitizer, sink").into(),
        );
    }

    // Validate cap
    if crate::labels::parse_cap(cap).is_none() {
        return Err(format!(
            "Invalid cap '{cap}'. Must be one of: env_var, html_escape, shell_escape, url_encode, json_parse, file_io, all"
        )
        .into());
    }

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
        kind: kind.to_string(),
        cap: cap.to_string(),
        case_sensitive: false,
    };

    // Dedup
    if !lang_cfg.rules.contains(&new_rule) {
        lang_cfg.rules.push(new_rule);
    }

    write_local_config(&local_path, &config)?;

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

    write_local_config(&local_path, &config)?;

    println!(
        "{}: Added terminator `{}` for {}",
        style("ok").green().bold(),
        name,
        lang
    );
    Ok(())
}

/// Write only the non-default portions to nyx.local.
fn write_local_config(path: &Path, config: &Config) -> NyxResult<()> {
    // Only write the analysis section to nyx.local to keep it minimal.
    // Other settings keep their defaults unless previously customized.
    let mut local = Config {
        analysis: config.analysis.clone(),
        ..Config::default()
    };

    // Strip empty language entries
    local.analysis.languages.retain(|_, v| {
        !v.rules.is_empty() || !v.terminators.is_empty() || !v.event_handlers.is_empty()
    });

    // If no analysis rules, only write the analysis section
    if local.analysis.languages.is_empty() {
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
        assert_eq!(js.rules[0].kind, "sanitizer");
        assert_eq!(js.rules[0].cap, "html_escape");
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
