use crate::utils::config::Config;

#[derive(Debug, Clone)]
pub struct AuthAnalysisRules {
    pub enabled: bool,
    pub finding_prefix: String,
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
            finding_prefix: "auth".into(),
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
        let normalized = if lower.starts_with('/') {
            lower.clone()
        } else {
            format!("/{lower}")
        };
        self.admin_path_patterns
            .iter()
            .map(|p| p.to_ascii_lowercase())
            .any(|p| normalized.contains(&p) || lower.contains(p.trim_matches('/')))
    }

    pub fn is_admin_guard(&self, name: &str, args: &[String]) -> bool {
        if self
            .admin_guard_names
            .iter()
            .any(|pattern| matches_name(name, pattern))
        {
            return true;
        }

        if matches_name(name, "requireRole")
            && args
                .first()
                .is_some_and(|arg| strip_quotes(arg).eq_ignore_ascii_case("admin"))
        {
            return true;
        }

        if matches_name(name, "permission_required")
            || matches_name(name, "PermissionRequiredMixin")
            || matches_name(name, "user_passes_test")
        {
            return args.iter().any(|arg| {
                let lower = strip_quotes(arg).to_ascii_lowercase();
                lower.contains("admin")
                    || lower.contains("staff")
                    || lower.contains("manage")
                    || lower.contains("auth.")
                    || lower.contains("change_")
                    || lower.contains("delete_")
                    || lower.contains("add_")
            });
        }

        false
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

    pub fn is_token_lookup_call(&self, name: &str, call_text: &str) -> bool {
        if self.is_token_lookup(name) {
            return true;
        }

        let lower = call_text.to_ascii_lowercase();
        let looks_like_token_query = lower.contains("token=")
            || lower.contains("token =")
            || lower.contains("invite")
            || lower.contains("invitation")
            || lower.contains("accept_key");

        looks_like_token_query
            && (self.is_read(name)
                || matches_name(name, "get")
                || matches_name(name, "filter")
                || matches_name(name, "first")
                || matches_name(name, "one"))
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

    pub fn rule_id(&self, suffix: &str) -> String {
        format!("{}.{}", self.finding_prefix, suffix)
    }
}

pub fn build_auth_rules(config: &Config, lang_slug: &str) -> AuthAnalysisRules {
    if !matches!(lang_slug, "javascript" | "typescript" | "python") {
        return AuthAnalysisRules::disabled();
    }

    let mut rules = if matches!(lang_slug, "python") {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: "py.auth".into(),
            admin_path_patterns: vec!["/admin/".into()],
            admin_guard_names: vec![
                "admin_required".into(),
                "staff_member_required".into(),
                "is_admin".into(),
                "is_staff".into(),
                "permission_required".into(),
                "PermissionRequiredMixin".into(),
                "AdminRequiredMixin".into(),
            ],
            login_guard_names: vec![
                "login_required".into(),
                "LoginRequiredMixin".into(),
                "require_login".into(),
                "ensure_authenticated".into(),
                "require_auth".into(),
            ],
            authorization_check_names: vec![
                "check_membership".into(),
                "has_membership".into(),
                "require_membership".into(),
                "ensure_membership".into(),
                "is_member".into(),
                "check_ownership".into(),
                "has_ownership".into(),
                "require_ownership".into(),
                "ensure_ownership".into(),
                "is_owner".into(),
                "owns_".into(),
                "permission_required".into(),
                "has_perm".into(),
                "has_permission".into(),
                "has_object_permission".into(),
                "user_passes_test".into(),
                "verify_access".into(),
                "authorize".into(),
            ],
            mutation_indicator_names: vec![
                "update".into(),
                "delete".into(),
                "create".into(),
                "save".into(),
                "bulk_update".into(),
                "bulk_create".into(),
                "archive".into(),
                "publish".into(),
                "remove".into(),
                "add".into(),
                "confirm".into(),
                "invite".into(),
                "accept".into(),
            ],
            read_indicator_names: vec![
                "get".into(),
                "filter".into(),
                "find".into(),
                "fetch".into(),
                "load".into(),
                "list".into(),
                "retrieve".into(),
            ],
            token_lookup_names: vec![
                "find_by_token".into(),
                "lookup_by_token".into(),
                "get_by_token".into(),
                "get_invitation_by_token".into(),
                "Invitation.objects.get".into(),
                "invite_lookup".into(),
            ],
            token_expiry_fields: vec![
                "expires_at".into(),
                "expiresat".into(),
                "expiry".into(),
                "expires".into(),
                "expired".into(),
                "has_expired".into(),
            ],
            token_recipient_fields: vec![
                "email".into(),
                "recipient_email".into(),
                "recipientemail".into(),
                "invited_email".into(),
                "invitedemail".into(),
                "recipient".into(),
            ],
        }
    } else {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: "js.auth".into(),
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
        }
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

pub fn extend_unique(dst: &mut Vec<String>, src: &[String]) {
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
