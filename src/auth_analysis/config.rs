use crate::utils::config::Config;

#[derive(Debug, Clone)]
pub struct AuthAnalysisRules {
    pub enabled: bool,
    pub admin_path_patterns: Vec<String>,
    pub admin_guard_names: Vec<String>,
    pub login_guard_names: Vec<String>,
    pub authorization_check_names: Vec<String>,
    pub mutation_indicator_names: Vec<String>,
    pub read_indicator_names: Vec<String>,
    pub token_lookup_names: Vec<String>,
    pub token_expiry_fields: Vec<String>,
    pub token_recipient_fields: Vec<String>,
}

impl AuthAnalysisRules {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            admin_path_patterns: Vec::new(),
            admin_guard_names: Vec::new(),
            login_guard_names: Vec::new(),
            authorization_check_names: Vec::new(),
            mutation_indicator_names: Vec::new(),
            read_indicator_names: Vec::new(),
            token_lookup_names: Vec::new(),
            token_expiry_fields: Vec::new(),
            token_recipient_fields: Vec::new(),
        }
    }

    pub fn requires_admin_path(&self, path: &str) -> bool {
        let lower = path.to_ascii_lowercase();
        self.admin_path_patterns
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .any(|p| lower.contains(&p))
    }

    pub fn is_admin_guard(&self, name: &str, args: &[String]) -> bool {
        if self
            .admin_guard_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
        {
            return true;
        }

        matches_name(name, "requireRole")
            && args
                .first()
                .is_some_and(|arg| strip_quotes(arg).eq_ignore_ascii_case("admin"))
    }

    pub fn is_login_guard(&self, name: &str) -> bool {
        self.login_guard_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
    }

    pub fn is_authorization_check(&self, name: &str) -> bool {
        self.authorization_check_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
    }

    pub fn is_token_lookup(&self, name: &str) -> bool {
        self.token_lookup_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
    }

    pub fn is_mutation(&self, name: &str) -> bool {
        self.mutation_indicator_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
    }

    pub fn is_read(&self, name: &str) -> bool {
        self.read_indicator_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
    }

    pub fn has_expiry_field(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        self.token_expiry_fields
            .iter()
            .map(|field| field.to_ascii_lowercase())
            .any(|field| lower.contains(&field))
    }

    pub fn has_recipient_field(&self, text: &str) -> bool {
        let lower = text.to_ascii_lowercase();
        self.token_recipient_fields
            .iter()
            .map(|field| field.to_ascii_lowercase())
            .any(|field| lower.contains(&field))
    }
}

pub fn build_auth_rules(config: &Config, lang_slug: &str) -> AuthAnalysisRules {
    if !matches!(lang_slug, "javascript" | "typescript") {
        return AuthAnalysisRules::disabled();
    }

    let mut rules = AuthAnalysisRules {
        enabled: true,
        admin_path_patterns: vec!["/admin/".into()],
        admin_guard_names: vec![
            "requireAdmin".into(),
            "isAdmin".into(),
            "adminOnly".into(),
            "requireRole".into(),
        ],
        login_guard_names: vec![
            "requireLogin".into(),
            "authenticate".into(),
            "requireAuth".into(),
            "ensureAuthenticated".into(),
            "ensureAuth".into(),
            "require_login".into(),
        ],
        authorization_check_names: vec![
            "checkMembership".into(),
            "hasWorkspaceMembership".into(),
            "checkOwnership".into(),
            "authorize".into(),
            "hasAccess".into(),
            "isOwner".into(),
            "isMember".into(),
            "requireMembership".into(),
            "requireOwnership".into(),
            "verifyAccess".into(),
            "hasPermission".into(),
            "requireRole".into(),
            "canAccess".into(),
        ],
        mutation_indicator_names: vec![
            "update".into(),
            "delete".into(),
            "create".into(),
            "archive".into(),
            "publish".into(),
            "remove".into(),
            "insert".into(),
            "add".into(),
            "confirm".into(),
            "invite".into(),
            "run".into(),
            "accept".into(),
        ],
        read_indicator_names: vec![
            "findById".into(),
            "find".into(),
            "list".into(),
            "get".into(),
            "fetch".into(),
            "load".into(),
        ],
        token_lookup_names: vec!["findByToken".into(), "lookupByToken".into()],
        token_expiry_fields: vec!["expires_at".into(), "expiresAt".into(), "expiry".into()],
        token_recipient_fields: vec![
            "email".into(),
            "recipient_email".into(),
            "recipientEmail".into(),
            "invited_email".into(),
            "invitedEmail".into(),
        ],
    };

    if let Some(lang_cfg) = config.analysis.languages.get(lang_slug) {
        rules.enabled = lang_cfg.auth.enabled;
        extend_unique(
            &mut rules.admin_path_patterns,
            &lang_cfg.auth.admin_path_patterns,
        );
        extend_unique(
            &mut rules.admin_guard_names,
            &lang_cfg.auth.admin_guard_names,
        );
        extend_unique(
            &mut rules.login_guard_names,
            &lang_cfg.auth.login_guard_names,
        );
        extend_unique(
            &mut rules.authorization_check_names,
            &lang_cfg.auth.authorization_check_names,
        );
        extend_unique(
            &mut rules.mutation_indicator_names,
            &lang_cfg.auth.mutation_indicator_names,
        );
        extend_unique(
            &mut rules.read_indicator_names,
            &lang_cfg.auth.read_indicator_names,
        );
        extend_unique(
            &mut rules.token_lookup_names,
            &lang_cfg.auth.token_lookup_names,
        );
        extend_unique(
            &mut rules.token_expiry_fields,
            &lang_cfg.auth.token_expiry_fields,
        );
        extend_unique(
            &mut rules.token_recipient_fields,
            &lang_cfg.auth.token_recipient_fields,
        );
    }

    rules
}

fn extend_unique(dst: &mut Vec<String>, src: &[String]) {
    for item in src {
        if !dst.contains(item) {
            dst.push(item.clone());
        }
    }
}

pub fn canonical_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

pub fn matches_name(name: &str, pattern: &str) -> bool {
    let name_last = name.rsplit('.').next().unwrap_or(name);
    let pattern_last = pattern.rsplit('.').next().unwrap_or(pattern);
    let name_norm = canonical_name(name_last);
    let pattern_norm = canonical_name(pattern_last);
    !pattern_norm.is_empty() && (name_norm == pattern_norm || name_norm.starts_with(&pattern_norm))
}

pub fn strip_quotes(input: &str) -> String {
    input
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .trim_matches('`')
        .to_string()
}
