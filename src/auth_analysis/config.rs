use crate::auth_analysis::model::SinkClass;
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
    pub non_sink_receiver_types: Vec<String>,
    pub non_sink_receiver_name_prefixes: Vec<String>,
    /// Receiver-chain first-segment prefixes that classify a call as a
    /// realtime publish (pub/sub, websocket, event stream).
    pub realtime_receiver_prefixes: Vec<String>,
    /// Receiver-chain prefixes that classify a call as an outbound
    /// network sink (HTTP client, RPC caller).
    pub outbound_network_receiver_prefixes: Vec<String>,
    /// Receiver-chain prefixes that classify a call as a cross-tenant
    /// cache access.
    pub cache_receiver_prefixes: Vec<String>,
    /// ACL tables that, when JOIN-ed in a SELECT and pinned via
    /// `WHERE <ACL>.user_id = ?N`, make every returned row
    /// membership-gated.  See `sql_semantics::classify_sql_query`.
    pub acl_tables: Vec<String>,
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
            non_sink_receiver_types: Vec::new(),
            non_sink_receiver_name_prefixes: Vec::new(),
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
        }
    }

    /// Last path segment of a type name (e.g. `std::collections::HashMap` → `HashMap`).
    /// Accepts either `::` or `.` as the path separator.
    fn type_last_segment(ty: &str) -> &str {
        let trimmed = ty
            .trim()
            .trim_start_matches('&')
            .trim_start_matches("mut ")
            .trim();
        let after_colons = trimmed.rsplit("::").next().unwrap_or(trimmed);
        after_colons.rsplit('.').next().unwrap_or(after_colons)
    }

    /// Does `ty` (last path segment, case-sensitive) match a
    /// non-sink receiver type?  The angle-bracket generic suffix is
    /// stripped first: `HashMap<i64, String>` → `HashMap`.
    pub fn is_non_sink_receiver_type(&self, ty: &str) -> bool {
        let base = Self::type_last_segment(ty);
        let base = base.split('<').next().unwrap_or(base).trim();
        self.non_sink_receiver_types
            .iter()
            .any(|allowed| allowed == base)
    }

    /// Does the callee of a constructor expression (e.g. `HashMap::new`,
    /// `SmallVec::from`, `Vec::with_capacity`) produce a non-sink
    /// receiver?  Matches when the type prefix is in
    /// `non_sink_receiver_types` AND the method is a known
    /// constructor verb.
    ///
    /// The callee string may use either `::` or `.` as the path
    /// separator (nyx's `callee_name` normalizes both via
    /// `member_chain`).
    pub fn is_non_sink_constructor_callee(&self, callee: &str) -> bool {
        let normalized = callee.replace("::", ".");
        let Some((ty, method)) = normalized.rsplit_once('.') else {
            return false;
        };
        if !self.is_non_sink_receiver_type(ty) {
            return false;
        }
        matches!(
            method,
            "new"
                | "with_capacity"
                | "with_capacity_and_hasher"
                | "with_hasher"
                | "from"
                | "from_iter"
                | "new_in"
                | "default"
        )
    }

    /// Does the first segment of a callee receiver chain look like a
    /// non-sink local variable, based on configured name prefixes?
    /// Used as a fallback when the type/binding cannot be resolved.
    pub fn receiver_matches_non_sink_prefix(&self, first_segment: &str) -> bool {
        if first_segment.is_empty() {
            return false;
        }
        self.non_sink_receiver_name_prefixes
            .iter()
            .any(|prefix| !prefix.is_empty() && first_segment.starts_with(prefix.as_str()))
    }

    /// Should a call on `callee` be skipped for Read/Mutation
    /// classification because its receiver is a local non-sink
    /// collection?  The `non_sink_vars` set lists variable names
    /// flagged during the unit walk (e.g. `let mut counts = HashMap::new()`).
    pub fn callee_has_non_sink_receiver(
        &self,
        callee: &str,
        non_sink_vars: &std::collections::HashSet<String>,
    ) -> bool {
        let first = first_receiver_segment(callee);
        if first.is_empty() {
            return false;
        }
        if non_sink_vars.contains(first) {
            return true;
        }
        self.receiver_matches_non_sink_prefix(first)
    }

    /// Does the first segment of the callee's receiver chain match any
    /// configured prefix in `prefixes`?  Comparison is case-insensitive
    /// on the first segment and uses starts-with on each prefix.
    fn receiver_matches_any_prefix(&self, first_segment: &str, prefixes: &[String]) -> bool {
        if first_segment.is_empty() {
            return false;
        }
        let lower = first_segment.to_ascii_lowercase();
        prefixes.iter().any(|prefix| {
            !prefix.is_empty() && lower.starts_with(prefix.to_ascii_lowercase().as_str())
        })
    }

    /// Classify a call into a [`SinkClass`].
    ///
    /// Dispatch order (first match wins):
    ///   1. `InMemoryLocal` — receiver is a known non-sink collection
    ///      (tracked in `non_sink_vars` or matches a configured
    ///      non-sink prefix).
    ///   2. `RealtimePublish` — receiver first-segment matches a
    ///      configured realtime prefix (e.g. `realtime`, `pubsub`).
    ///   3. `OutboundNetwork` — receiver first-segment matches a
    ///      configured outbound-network prefix (e.g. `http`, `reqwest`).
    ///   4. `CacheCrossTenant` — receiver first-segment matches a
    ///      configured cache prefix (e.g. `cache`, `redis`).
    ///   5. `DbMutation` — callee name matches `mutation_indicator_names`.
    ///   6. `DbCrossTenantRead` — callee name matches `read_indicator_names`.
    ///
    /// Returns `None` when the callee matches none of the above — the
    /// call site is ignored by ownership-gap checks.
    pub fn classify_sink_class(
        &self,
        callee: &str,
        non_sink_vars: &std::collections::HashSet<String>,
    ) -> Option<SinkClass> {
        if self.callee_has_non_sink_receiver(callee, non_sink_vars) {
            return Some(SinkClass::InMemoryLocal);
        }
        let first = first_receiver_segment(callee);
        if self.receiver_matches_any_prefix(first, &self.realtime_receiver_prefixes) {
            return Some(SinkClass::RealtimePublish);
        }
        if self.receiver_matches_any_prefix(first, &self.outbound_network_receiver_prefixes) {
            return Some(SinkClass::OutboundNetwork);
        }
        if self.receiver_matches_any_prefix(first, &self.cache_receiver_prefixes) {
            return Some(SinkClass::CacheCrossTenant);
        }
        if self.is_mutation(callee) {
            return Some(SinkClass::DbMutation);
        }
        if self.is_read(callee) {
            return Some(SinkClass::DbCrossTenantRead);
        }
        None
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
        if matches_name(name, "PreAuthorize")
            || matches_name(name, "Secured")
            || matches_name(name, "RolesAllowed")
            || matches_name(name, "hasRole")
            || matches_name(name, "hasAuthority")
        {
            return args.iter().any(|arg| {
                let lower = strip_quotes(arg).to_ascii_lowercase();
                lower.contains("admin")
                    || lower.contains("role_admin")
                    || lower.contains("manage")
                    || lower.contains("superuser")
            });
        }

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
        if matches_name(name, "isAuthenticated")
            || matches_name(name, "authenticated")
            || matches_name(name, "hasRole")
            || matches_name(name, "hasAuthority")
            || matches_name(name, "Secured")
            || matches_name(name, "RolesAllowed")
            || matches_name(name, "PreAuthorize")
        {
            return true;
        }

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

fn auth_finding_prefix(lang_slug: &str) -> Option<&'static str> {
    match lang_slug {
        "javascript" | "typescript" => Some("js.auth"),
        "python" => Some("py.auth"),
        "ruby" => Some("rb.auth"),
        "go" => Some("go.auth"),
        "java" => Some("java.auth"),
        "rust" => Some("rs.auth"),
        _ => None,
    }
}

fn auth_config_slugs(lang_slug: &str) -> &'static [&'static str] {
    match lang_slug {
        "typescript" => &["javascript", "typescript"],
        "javascript" => &["javascript"],
        "python" => &["python"],
        "ruby" => &["ruby"],
        "go" => &["go"],
        "java" => &["java"],
        "rust" => &["rust"],
        _ => &[],
    }
}

pub fn build_auth_rules(config: &Config, lang_slug: &str) -> AuthAnalysisRules {
    let Some(finding_prefix) = auth_finding_prefix(lang_slug) else {
        return AuthAnalysisRules::disabled();
    };

    let mut rules = if matches!(lang_slug, "python") {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
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
            non_sink_receiver_types: Vec::new(),
            non_sink_receiver_name_prefixes: Vec::new(),
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
        }
    } else if matches!(lang_slug, "ruby") {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
            admin_path_patterns: vec!["/admin/".into()],
            admin_guard_names: vec![
                "require_admin".into(),
                "require_admin!".into(),
                "authenticate_admin".into(),
                "authenticate_admin!".into(),
                "ensure_admin".into(),
                "ensure_admin!".into(),
                "admin_only".into(),
                "admin_only!".into(),
                "admin_required".into(),
                "admin_required!".into(),
            ],
            login_guard_names: vec![
                "require_login".into(),
                "require_login!".into(),
                "authenticate_user".into(),
                "authenticate_user!".into(),
                "authenticate".into(),
                "authenticate!".into(),
                "ensure_authenticated".into(),
                "ensure_authenticated!".into(),
                "login_required".into(),
                "login_required!".into(),
            ],
            authorization_check_names: vec![
                "authorize".into(),
                "authorize!".into(),
                "check_membership".into(),
                "check_membership!".into(),
                "has_membership".into(),
                "has_membership?".into(),
                "require_membership".into(),
                "require_membership!".into(),
                "ensure_membership".into(),
                "ensure_membership!".into(),
                "member_of?".into(),
                "member?".into(),
                "check_ownership".into(),
                "check_ownership!".into(),
                "has_ownership".into(),
                "has_ownership?".into(),
                "require_ownership".into(),
                "require_ownership!".into(),
                "ensure_ownership".into(),
                "ensure_ownership!".into(),
                "owner?".into(),
                "owns?".into(),
                "verify_access".into(),
                "verify_access!".into(),
                "can_access?".into(),
                "can?".into(),
            ],
            mutation_indicator_names: vec![
                "update".into(),
                "update!".into(),
                "delete".into(),
                "delete!".into(),
                "destroy".into(),
                "destroy!".into(),
                "create".into(),
                "create!".into(),
                "save".into(),
                "save!".into(),
                "archive".into(),
                "archive!".into(),
                "publish".into(),
                "publish!".into(),
                "remove".into(),
                "remove!".into(),
                "add".into(),
                "add!".into(),
                "confirm".into(),
                "confirm!".into(),
                "invite".into(),
                "invite!".into(),
                "accept".into(),
                "accept!".into(),
            ],
            read_indicator_names: vec![
                "find".into(),
                "find_by".into(),
                "find_by!".into(),
                "where".into(),
                "first".into(),
                "last".into(),
                "take".into(),
                "pluck".into(),
                "load".into(),
                "fetch".into(),
                "get".into(),
                "lookup".into(),
                "retrieve".into(),
            ],
            token_lookup_names: vec![
                "find_by_token".into(),
                "find_by_token!".into(),
                "find_by_invite_token".into(),
                "find_by_invite_token!".into(),
                "find_by_invitation_token".into(),
                "find_by_invitation_token!".into(),
                "find_by_accept_token".into(),
                "find_by_accept_token!".into(),
                "find_signed".into(),
                "find_signed!".into(),
                "lookup_invitation".into(),
                "lookup_invitation!".into(),
                "Invitation.find_by".into(),
                "Invitation.find_by!".into(),
                "Invite.find_by".into(),
                "Invite.find_by!".into(),
            ],
            token_expiry_fields: vec![
                "expires_at".into(),
                "expiry".into(),
                "expires".into(),
                "expired".into(),
                "expired?".into(),
                "expired_at".into(),
                "valid_until".into(),
            ],
            token_recipient_fields: vec![
                "email".into(),
                "recipient_email".into(),
                "recipient".into(),
                "invited_email".into(),
                "invitee_email".into(),
                "user_email".into(),
            ],
            non_sink_receiver_types: Vec::new(),
            non_sink_receiver_name_prefixes: Vec::new(),
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
        }
    } else if matches!(lang_slug, "go") {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
            admin_path_patterns: vec!["/admin/".into()],
            admin_guard_names: vec![
                "RequireAdmin".into(),
                "AdminOnly".into(),
                "EnsureAdmin".into(),
                "requireAdmin".into(),
                "adminOnly".into(),
                "ensureAdmin".into(),
            ],
            login_guard_names: vec![
                "RequireLogin".into(),
                "RequireAuth".into(),
                "EnsureAuthenticated".into(),
                "AuthMiddleware".into(),
                "requireLogin".into(),
                "requireAuth".into(),
                "ensureAuthenticated".into(),
            ],
            authorization_check_names: vec![
                "CheckMembership".into(),
                "HasMembership".into(),
                "RequireMembership".into(),
                "EnsureMembership".into(),
                "IsMember".into(),
                "CheckOwnership".into(),
                "HasOwnership".into(),
                "RequireOwnership".into(),
                "EnsureOwnership".into(),
                "IsOwner".into(),
                "Authorize".into(),
                "VerifyAccess".into(),
                "HasPermission".into(),
                "CanAccess".into(),
            ],
            mutation_indicator_names: vec![
                "Update".into(),
                "Delete".into(),
                "Create".into(),
                "Save".into(),
                "Archive".into(),
                "Publish".into(),
                "Remove".into(),
                "Add".into(),
                "Confirm".into(),
                "Invite".into(),
                "Accept".into(),
            ],
            read_indicator_names: vec![
                "Find".into(),
                "Get".into(),
                "List".into(),
                "Load".into(),
                "Fetch".into(),
                "Lookup".into(),
                "Query".into(),
            ],
            token_lookup_names: vec![
                "FindByToken".into(),
                "LookupByToken".into(),
                "FindInvitationByToken".into(),
                "FindInviteByToken".into(),
                "GetInvitationByToken".into(),
                "LookupInvitation".into(),
            ],
            token_expiry_fields: vec![
                "expires_at".into(),
                "expiresat".into(),
                "expiresAt".into(),
                "expiry".into(),
                "expired".into(),
                "validUntil".into(),
            ],
            token_recipient_fields: vec![
                "email".into(),
                "recipient_email".into(),
                "recipientEmail".into(),
                "invited_email".into(),
                "invitedEmail".into(),
                "invitee_email".into(),
                "inviteeEmail".into(),
                "recipient".into(),
            ],
            non_sink_receiver_types: Vec::new(),
            non_sink_receiver_name_prefixes: Vec::new(),
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
        }
    } else if matches!(lang_slug, "java") {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
            admin_path_patterns: vec!["/admin/".into()],
            admin_guard_names: vec![
                "RequireAdmin".into(),
                "AdminOnly".into(),
                "EnsureAdmin".into(),
                "adminOnly".into(),
            ],
            login_guard_names: vec![
                "RequireLogin".into(),
                "LoginRequired".into(),
                "EnsureAuthenticated".into(),
                "Authenticated".into(),
                "isAuthenticated".into(),
            ],
            authorization_check_names: vec![
                "checkMembership".into(),
                "hasMembership".into(),
                "requireMembership".into(),
                "ensureMembership".into(),
                "isMember".into(),
                "checkOwnership".into(),
                "hasOwnership".into(),
                "requireOwnership".into(),
                "ensureOwnership".into(),
                "isOwner".into(),
                "authorize".into(),
                "verifyAccess".into(),
                "hasPermission".into(),
                "canAccess".into(),
            ],
            mutation_indicator_names: vec![
                "update".into(),
                "delete".into(),
                "create".into(),
                "save".into(),
                "archive".into(),
                "publish".into(),
                "remove".into(),
                "add".into(),
                "confirm".into(),
                "invite".into(),
                "accept".into(),
            ],
            read_indicator_names: vec![
                "find".into(),
                "get".into(),
                "load".into(),
                "fetch".into(),
                "lookup".into(),
                "read".into(),
                "query".into(),
            ],
            token_lookup_names: vec![
                "findByToken".into(),
                "findByInviteToken".into(),
                "findByInvitationToken".into(),
                "findByAcceptToken".into(),
                "getByToken".into(),
                "lookupByToken".into(),
                "lookupInvitation".into(),
            ],
            token_expiry_fields: vec![
                "expires_at".into(),
                "expiresAt".into(),
                "expiry".into(),
                "expired".into(),
                "validUntil".into(),
            ],
            token_recipient_fields: vec![
                "email".into(),
                "recipient_email".into(),
                "recipientEmail".into(),
                "invited_email".into(),
                "invitedEmail".into(),
                "invitee_email".into(),
                "inviteeEmail".into(),
                "recipient".into(),
            ],
            non_sink_receiver_types: Vec::new(),
            non_sink_receiver_name_prefixes: Vec::new(),
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
        }
    } else if matches!(lang_slug, "rust") {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
            admin_path_patterns: vec!["/admin/".into()],
            admin_guard_names: vec![
                "require_admin".into(),
                "ensure_admin".into(),
                "admin_only".into(),
                "admin_guard".into(),
                "AdminUser".into(),
                "AdminGuard".into(),
                "RequireAdmin".into(),
            ],
            login_guard_names: vec![
                "require_login".into(),
                "require_auth".into(),
                "ensure_authenticated".into(),
                "authenticated".into(),
                "CurrentUser".into(),
                "SessionUser".into(),
                "AuthUser".into(),
                "RequireLogin".into(),
                "RequireAuth".into(),
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
                "authorize".into(),
                "verify_access".into(),
                "has_permission".into(),
                "can_access".into(),
                "can_manage".into(),
                // Common project-specific helpers seen in real Axum/Rocket
                // codebases — kept as defaults so user code that names
                // its membership helper after the resource still gets
                // recognised.  Users can extend via `nyx.toml`.
                "require_group_member".into(),
                "require_org_member".into(),
                "require_workspace_member".into(),
                "require_tenant_member".into(),
                "require_team_member".into(),
            ],
            mutation_indicator_names: vec![
                "update".into(),
                "delete".into(),
                "destroy".into(),
                "create".into(),
                "save".into(),
                "archive".into(),
                "publish".into(),
                "remove".into(),
                "insert".into(),
                "add".into(),
                "confirm".into(),
                "invite".into(),
                "accept".into(),
                "set".into(),
            ],
            read_indicator_names: vec![
                "find".into(),
                "find_by_id".into(),
                "get".into(),
                "load".into(),
                "fetch".into(),
                "lookup".into(),
                "list".into(),
                "read".into(),
                "query".into(),
            ],
            token_lookup_names: vec![
                "find_by_token".into(),
                "lookup_by_token".into(),
                "get_by_token".into(),
                "find_invitation_by_token".into(),
                "find_invite_by_token".into(),
                "lookup_invitation".into(),
                "get_invitation".into(),
                "find_by_invite_token".into(),
                "find_by_invitation_token".into(),
                "find_signed".into(),
            ],
            token_expiry_fields: vec![
                "expires_at".into(),
                "expiresat".into(),
                "expiresAt".into(),
                "expiry".into(),
                "expires".into(),
                "expired".into(),
                "valid_until".into(),
                "validUntil".into(),
            ],
            token_recipient_fields: vec![
                "email".into(),
                "recipient_email".into(),
                "recipientEmail".into(),
                "invited_email".into(),
                "invitedEmail".into(),
                "invitee_email".into(),
                "inviteeEmail".into(),
                "recipient".into(),
            ],
            non_sink_receiver_types: vec![
                "HashMap".into(),
                "HashSet".into(),
                "BTreeMap".into(),
                "BTreeSet".into(),
                "Vec".into(),
                "VecDeque".into(),
                "BinaryHeap".into(),
                "IndexMap".into(),
                "IndexSet".into(),
                "LinkedList".into(),
                "SmallVec".into(),
                "FxHashMap".into(),
                "FxHashSet".into(),
                "DashMap".into(),
                "DashSet".into(),
            ],
            non_sink_receiver_name_prefixes: vec![
                "local_map".into(),
                "local_set".into(),
                "local_cache".into(),
                "visited".into(),
                "seen".into(),
                "idx_".into(),
                "index_".into(),
                "lookup_".into(),
                "_tmp_map".into(),
                "counts".into(),
                "buckets".into(),
                "pending".into(),
                "queue".into(),
                "stack".into(),
            ],
            realtime_receiver_prefixes: vec![
                "realtime".into(),
                "pubsub".into(),
                "broker".into(),
                "broadcast".into(),
                "notifier".into(),
                "channels".into(),
            ],
            outbound_network_receiver_prefixes: vec![
                "http".into(),
                "reqwest".into(),
                "hyper".into(),
                "client".into(),
                "webhook".into(),
                "fetcher".into(),
            ],
            cache_receiver_prefixes: vec!["redis".into(), "memcache".into(), "memcached".into()],
            acl_tables: vec![
                "group_members".into(),
                "org_memberships".into(),
                "workspace_members".into(),
                "tenant_members".into(),
                "members".into(),
                "share_grants".into(),
            ],
        }
    } else {
        AuthAnalysisRules {
            enabled: true,
            finding_prefix: finding_prefix.into(),
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
            non_sink_receiver_types: Vec::new(),
            non_sink_receiver_name_prefixes: Vec::new(),
            realtime_receiver_prefixes: Vec::new(),
            outbound_network_receiver_prefixes: Vec::new(),
            cache_receiver_prefixes: Vec::new(),
            acl_tables: Vec::new(),
        }
    };

    for config_slug in auth_config_slugs(lang_slug) {
        let Some(lang_cfg) = config.analysis.languages.get(*config_slug) else {
            continue;
        };
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
        extend_unique(
            &mut rules.non_sink_receiver_types,
            &lang_cfg.auth.non_sink_receiver_types,
        );
        extend_unique(
            &mut rules.non_sink_receiver_name_prefixes,
            &lang_cfg.auth.non_sink_receiver_name_prefixes,
        );
        extend_unique(
            &mut rules.realtime_receiver_prefixes,
            &lang_cfg.auth.realtime_receiver_prefixes,
        );
        extend_unique(
            &mut rules.outbound_network_receiver_prefixes,
            &lang_cfg.auth.outbound_network_receiver_prefixes,
        );
        extend_unique(
            &mut rules.cache_receiver_prefixes,
            &lang_cfg.auth.cache_receiver_prefixes,
        );
        extend_unique(&mut rules.acl_tables, &lang_cfg.auth.acl_tables);
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

/// Return the first segment of a callee's receiver chain.
/// For `map.insert` → `"map"`; for `self.cache.insert` → `"self"`;
/// for a callee with no receiver (`HashMap::new`) → the full name.
pub fn first_receiver_segment(callee: &str) -> &str {
    callee.split('.').next().unwrap_or(callee)
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

#[cfg(test)]
mod tests {
    use super::build_auth_rules;
    use crate::utils::config::{AuthAnalysisConfig, Config, LanguageAnalysisConfig};

    #[test]
    fn typescript_uses_javascript_rule_prefix() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "typescript");
        assert_eq!(
            rules.rule_id("missing_ownership_check"),
            "js.auth.missing_ownership_check"
        );
    }

    #[test]
    fn typescript_inherits_javascript_auth_overrides_and_applies_ts_specific_overlay() {
        let mut cfg = Config::default();
        cfg.analysis.languages.insert(
            "javascript".into(),
            LanguageAnalysisConfig {
                auth: AuthAnalysisConfig {
                    admin_guard_names: vec!["requirePlatformAdmin".into()],
                    token_lookup_names: vec!["findInviteToken".into()],
                    ..AuthAnalysisConfig::default()
                },
                ..LanguageAnalysisConfig::default()
            },
        );
        cfg.analysis.languages.insert(
            "typescript".into(),
            LanguageAnalysisConfig {
                auth: AuthAnalysisConfig {
                    authorization_check_names: vec!["requireTypedOwnership".into()],
                    ..AuthAnalysisConfig::default()
                },
                ..LanguageAnalysisConfig::default()
            },
        );

        let rules = build_auth_rules(&cfg, "typescript");

        assert!(
            rules
                .admin_guard_names
                .contains(&"requirePlatformAdmin".to_string())
        );
        assert!(
            rules
                .token_lookup_names
                .contains(&"findInviteToken".to_string())
        );
        assert!(
            rules
                .authorization_check_names
                .contains(&"requireTypedOwnership".to_string())
        );
    }

    #[test]
    fn rust_non_sink_receiver_defaults_include_std_collections() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        assert!(rules.is_non_sink_receiver_type("HashMap"));
        assert!(rules.is_non_sink_receiver_type("HashSet"));
        assert!(rules.is_non_sink_receiver_type("Vec"));
        assert!(rules.is_non_sink_receiver_type("std::collections::HashMap"));
        assert!(rules.is_non_sink_receiver_type("HashMap<i64, usize>"));
        assert!(!rules.is_non_sink_receiver_type("Database"));
    }

    #[test]
    fn rust_non_sink_constructor_callee_matches_known_forms() {
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        assert!(rules.is_non_sink_constructor_callee("HashMap::new"));
        assert!(rules.is_non_sink_constructor_callee("HashMap::with_capacity"));
        assert!(rules.is_non_sink_constructor_callee("SmallVec::from"));
        assert!(rules.is_non_sink_constructor_callee("std::collections::HashMap::new"));
        assert!(!rules.is_non_sink_constructor_callee("HashMap::get"));
        assert!(!rules.is_non_sink_constructor_callee("Database::connect"));
        assert!(!rules.is_non_sink_constructor_callee("plain_function"));
    }

    #[test]
    fn callee_has_non_sink_receiver_matches_var_set_and_prefixes() {
        use std::collections::HashSet;
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        let mut vars = HashSet::new();
        vars.insert("map".to_string());

        // First receiver segment in non_sink_vars → skipped.
        assert!(rules.callee_has_non_sink_receiver("map.insert", &vars));
        // First segment not in vars, not a known prefix → not skipped.
        assert!(!rules.callee_has_non_sink_receiver("db.insert", &vars));
        // Deep receiver: "self.cache.insert" → first segment "self" → ambiguous.
        assert!(!rules.callee_has_non_sink_receiver("self.cache.insert", &vars));
        // Prefix-match on configured name prefix ("counts" is in defaults).
        assert!(rules.callee_has_non_sink_receiver("counts.insert", &HashSet::new()));
        assert!(rules.callee_has_non_sink_receiver("visited_nodes.insert", &HashSet::new()));
    }

    #[test]
    fn classify_sink_class_dispatches_on_receiver_and_name() {
        use crate::auth_analysis::model::SinkClass;
        use std::collections::HashSet;
        let cfg = Config::default();
        let rules = build_auth_rules(&cfg, "rust");
        let mut vars = HashSet::new();
        vars.insert("map".to_string());

        // In-memory local: tracked var → InMemoryLocal (trumps name-based match).
        assert_eq!(
            rules.classify_sink_class("map.insert", &vars),
            Some(SinkClass::InMemoryLocal)
        );
        // In-memory local: configured name prefix.
        assert_eq!(
            rules.classify_sink_class("visited.insert", &HashSet::new()),
            Some(SinkClass::InMemoryLocal)
        );
        // Realtime: default prefix `realtime` → RealtimePublish even when
        // the method name (`publish_to_group`) would also match the
        // mutation list.
        assert_eq!(
            rules.classify_sink_class("realtime.publish_to_group", &HashSet::new()),
            Some(SinkClass::RealtimePublish)
        );
        // Outbound network: default prefix `http`.
        assert_eq!(
            rules.classify_sink_class("http.post", &HashSet::new()),
            Some(SinkClass::OutboundNetwork)
        );
        // Cache: default prefix `redis`.
        assert_eq!(
            rules.classify_sink_class("redis.set", &HashSet::new()),
            Some(SinkClass::CacheCrossTenant)
        );
        // DB mutation fallback: `db.insert` → mutation indicator →
        // DbMutation (no receiver prefix matches `db`).
        assert_eq!(
            rules.classify_sink_class("db.insert", &HashSet::new()),
            Some(SinkClass::DbMutation)
        );
        // DB cross-tenant read fallback: `db.find_by_id` → read indicator.
        assert_eq!(
            rules.classify_sink_class("db.find_by_id", &HashSet::new()),
            Some(SinkClass::DbCrossTenantRead)
        );
        // Unknown verb with unknown receiver → None.
        assert_eq!(
            rules.classify_sink_class("widget.frobnicate", &HashSet::new()),
            None
        );
    }

    #[test]
    fn sink_class_is_auth_relevant_only_for_non_local_classes() {
        use crate::auth_analysis::model::SinkClass;
        assert!(SinkClass::DbMutation.is_auth_relevant());
        assert!(SinkClass::DbCrossTenantRead.is_auth_relevant());
        assert!(SinkClass::RealtimePublish.is_auth_relevant());
        assert!(SinkClass::OutboundNetwork.is_auth_relevant());
        assert!(SinkClass::CacheCrossTenant.is_auth_relevant());
        assert!(!SinkClass::InMemoryLocal.is_auth_relevant());
    }
}
