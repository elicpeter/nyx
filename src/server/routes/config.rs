use crate::commands::config as config_cmd;
use crate::server::app::{AppState, ServerEvent};
use crate::server::models::{RuleView, TerminatorView};
use crate::utils::config::{CapName, RuleKind};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/config", get(get_config))
        .route(
            "/config/rules",
            get(list_rules).post(add_rule).delete(remove_rule),
        )
        .route(
            "/config/terminators",
            get(list_terminators)
                .post(add_terminator)
                .delete(remove_terminator),
        )
}

async fn get_config(State(state): State<AppState>) -> Json<serde_json::Value> {
    let config = state.config.read().unwrap();
    Json(serde_json::to_value(&*config).unwrap_or_default())
}

async fn list_rules(State(state): State<AppState>) -> Json<Vec<RuleView>> {
    let config = state.config.read().unwrap();
    let mut rules = Vec::new();
    for (lang, lang_cfg) in &config.analysis.languages {
        for rule in &lang_cfg.rules {
            rules.push(RuleView {
                lang: lang.clone(),
                matchers: rule.matchers.clone(),
                kind: rule.kind.to_string(),
                cap: format!("{:?}", rule.cap).to_ascii_lowercase(),
            });
        }
    }
    Json(rules)
}

async fn add_rule(
    State(state): State<AppState>,
    Json(rule): Json<RuleView>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let rule_kind: RuleKind = rule
        .kind
        .parse()
        .map_err(|e: String| bad_request(&e))?;
    let cap_name: CapName = rule
        .cap
        .parse()
        .map_err(|e: String| bad_request(&e))?;

    // Load current local config, apply change, write back.
    if let Err(e) = config_cmd::add_rule(
        &state.config_dir,
        &rule.lang,
        &rule.matchers.join(","),
        &rule.kind,
        &rule.cap,
    ) {
        return Err(bad_request(&e.to_string()));
    }

    // Update in-memory config.
    {
        let mut config = state.config.write().unwrap();
        let lang_cfg = config
            .analysis
            .languages
            .entry(rule.lang.clone())
            .or_default();

        let new_rule = crate::utils::config::ConfigLabelRule {
            matchers: rule.matchers.clone(),
            kind: rule_kind,
            cap: cap_name,
            case_sensitive: false,
        };

        if !lang_cfg.rules.contains(&new_rule) {
            lang_cfg.rules.push(new_rule);
        }
    }

    let _ = state.event_tx.send(ServerEvent::ConfigChanged);

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok" })),
    ))
}

async fn remove_rule(
    State(state): State<AppState>,
    Json(rule): Json<RuleView>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let rule_kind: RuleKind = rule
        .kind
        .parse()
        .map_err(|e: String| bad_request(&e))?;
    let cap_name: CapName = rule
        .cap
        .parse()
        .map_err(|e: String| bad_request(&e))?;

    // Remove from in-memory config.
    let removed = {
        let mut config = state.config.write().unwrap();
        if let Some(lang_cfg) = config.analysis.languages.get_mut(&rule.lang) {
            let before = lang_cfg.rules.len();
            lang_cfg.rules.retain(|r| {
                !(r.matchers == rule.matchers && r.kind == rule_kind && r.cap == cap_name)
            });
            lang_cfg.rules.len() < before
        } else {
            false
        }
    };

    if removed {
        // Persist to disk.
        let config = state.config.read().unwrap();
        let local_path = state.config_dir.join("nyx.local");
        let _ = config_cmd::save_local_config(&local_path, &config);
        let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    }

    Ok(Json(serde_json::json!({ "removed": removed })))
}

async fn list_terminators(State(state): State<AppState>) -> Json<Vec<TerminatorView>> {
    let config = state.config.read().unwrap();
    let mut terminators = Vec::new();
    for (lang, lang_cfg) in &config.analysis.languages {
        for name in &lang_cfg.terminators {
            terminators.push(TerminatorView {
                lang: lang.clone(),
                name: name.clone(),
            });
        }
    }
    Json(terminators)
}

async fn add_terminator(
    State(state): State<AppState>,
    Json(term): Json<TerminatorView>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    if let Err(e) = config_cmd::add_terminator(&state.config_dir, &term.lang, &term.name) {
        return Err(bad_request(&e.to_string()));
    }

    // Update in-memory config.
    {
        let mut config = state.config.write().unwrap();
        let lang_cfg = config
            .analysis
            .languages
            .entry(term.lang.clone())
            .or_default();
        if !lang_cfg.terminators.contains(&term.name) {
            lang_cfg.terminators.push(term.name.clone());
        }
    }

    let _ = state.event_tx.send(ServerEvent::ConfigChanged);

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "ok" })),
    ))
}

async fn remove_terminator(
    State(state): State<AppState>,
    Json(term): Json<TerminatorView>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let removed = {
        let mut config = state.config.write().unwrap();
        if let Some(lang_cfg) = config.analysis.languages.get_mut(&term.lang) {
            let before = lang_cfg.terminators.len();
            lang_cfg.terminators.retain(|n| n != &term.name);
            lang_cfg.terminators.len() < before
        } else {
            false
        }
    };

    if removed {
        let config = state.config.read().unwrap();
        let local_path = state.config_dir.join("nyx.local");
        let _ = config_cmd::save_local_config(&local_path, &config);
        let _ = state.event_tx.send(ServerEvent::ConfigChanged);
    }

    Ok(Json(serde_json::json!({ "removed": removed })))
}

fn bad_request(msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": msg })),
    )
}
