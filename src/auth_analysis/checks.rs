use super::config::AuthAnalysisRules;
use super::model::{
    AnalysisUnit, AuthCheck, AuthCheckKind, AuthorizationModel, OperationKind, SensitiveOperation,
    ValueRef, ValueSourceKind,
};
use crate::patterns::Severity;

#[derive(Debug, Clone)]
pub struct AuthFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub span: (usize, usize),
    pub message: String,
}

pub fn run_checks(model: &AuthorizationModel, rules: &AuthAnalysisRules) -> Vec<AuthFinding> {
    let mut findings = Vec::new();
    findings.extend(check_admin_routes(model, rules));
    findings.extend(check_ownership_gaps(model, rules));
    findings.extend(check_partial_batch_authorization(model, rules));
    findings.extend(check_stale_authorization(model, rules));
    findings.extend(check_token_override_without_validation(model, rules));
    findings.sort_by(|a, b| a.span.cmp(&b.span).then_with(|| a.rule_id.cmp(&b.rule_id)));
    findings.dedup_by(|a, b| a.span == b.span && a.rule_id == b.rule_id);
    findings
}

fn check_admin_routes(model: &AuthorizationModel, rules: &AuthAnalysisRules) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for route in &model.routes {
        let Some(unit) = model.units.get(route.unit_idx) else {
            continue;
        };
        let requires_admin =
            rules.requires_admin_path(&route.path) || route_is_admin_sensitive(unit);
        if !requires_admin {
            continue;
        }

        let has_admin = route
            .middleware_calls
            .iter()
            .any(|mw| rules.is_admin_guard(&mw.name, &mw.args));
        let has_login = route
            .middleware_calls
            .iter()
            .any(|mw| rules.is_login_guard(&mw.name) || rules.is_admin_guard(&mw.name, &mw.args));

        if !has_admin && has_login {
            findings.push(AuthFinding {
                rule_id: rules.rule_id("admin_route_missing_admin_check"),
                severity: Severity::High,
                span: route.handler_span,
                message: format!(
                    "route `{}` appears admin-sensitive but its middleware only enforces login-level access",
                    route.path
                ),
            });
        }
    }

    findings
}

fn check_ownership_gaps(model: &AuthorizationModel, rules: &AuthAnalysisRules) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        for op in &unit.operations {
            if op.kind == OperationKind::TokenLookup {
                continue;
            }
            // `InMemoryLocal` sinks (HashMap/HashSet/Vec/… local
            // bookkeeping) are never authorization-relevant.
            if op.sink_class.is_some_and(|c| !c.is_auth_relevant()) {
                continue;
            }
            if op.kind == OperationKind::Read && unit_is_auth_helper(unit) {
                continue;
            }
            let relevant_subjects: Vec<&ValueRef> = op
                .subjects
                .iter()
                .filter(|s| is_relevant_target_subject(s, unit))
                .collect();
            if relevant_subjects.is_empty() {
                continue;
            }
            if op.kind == OperationKind::Read || op.kind == OperationKind::Mutation {
                if is_delegated_read_with_actor_context(unit, op, &relevant_subjects) {
                    continue;
                }
                if !has_prior_subject_auth(unit, op, &relevant_subjects) {
                    findings.push(AuthFinding {
                        rule_id: rules.rule_id("missing_ownership_check"),
                        severity: Severity::High,
                        span: op.span,
                        message: format!(
                            "operation `{}` uses scoped identifier input without a preceding ownership or membership check",
                            op.callee
                        ),
                    });
                }
            }
        }
    }

    findings
}

fn check_partial_batch_authorization(
    model: &AuthorizationModel,
    rules: &AuthAnalysisRules,
) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        for op in &unit.operations {
            // In-memory bookkeeping is never a batch sink.
            if op.sink_class.is_some_and(|c| !c.is_auth_relevant()) {
                continue;
            }
            let batch_subjects: Vec<&ValueRef> = op
                .subjects
                .iter()
                .filter(|subject| is_batch_collection(subject))
                .collect();
            if batch_subjects.is_empty() {
                continue;
            }

            let partial_check = unit.auth_checks.iter().any(|check| {
                check.line <= op.line
                    && check.subjects.iter().any(|subject| {
                        subject.source_kind == ValueSourceKind::ArrayIndex
                            && subject.base.as_ref().is_some_and(|base| {
                                batch_subjects
                                    .iter()
                                    .any(|op_subject| op_subject.name == *base)
                            })
                    })
            });
            let full_collection_check = has_prior_collection_auth(unit, op, &batch_subjects);

            if partial_check && !full_collection_check {
                findings.push(AuthFinding {
                    rule_id: rules.rule_id("partial_batch_authorization"),
                    severity: Severity::High,
                    span: op.span,
                    message: format!(
                        "batch operation `{}` authorizes only a single indexed element before acting on the full collection",
                        op.callee
                    ),
                });
            }
        }
    }

    findings
}

fn check_stale_authorization(
    model: &AuthorizationModel,
    rules: &AuthAnalysisRules,
) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        for op in unit.operations.iter().filter(|operation| {
            operation.kind == OperationKind::Mutation
                && operation.sink_class.is_none_or(|c| c.is_auth_relevant())
        }) {
            let session_subject = op.subjects.iter().any(is_stale_session_subject);
            if !session_subject {
                continue;
            }

            let has_fresh_auth = unit.auth_checks.iter().any(|check| {
                check.line <= op.line
                    && matches!(
                        check.kind,
                        AuthCheckKind::Ownership
                            | AuthCheckKind::Membership
                            | AuthCheckKind::AdminGuard
                            | AuthCheckKind::Other
                    )
            });

            if !has_fresh_auth {
                findings.push(AuthFinding {
                    rule_id: rules.rule_id("stale_authorization"),
                    severity: Severity::Medium,
                    span: op.span,
                    message: format!(
                        "mutation `{}` relies on session-carried state without a fresh authorization check",
                        op.callee
                    ),
                });
            }
        }
    }

    findings
}

fn check_token_override_without_validation(
    model: &AuthorizationModel,
    rules: &AuthAnalysisRules,
) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        let Some(token_lookup) = unit
            .operations
            .iter()
            .find(|operation| operation.kind == OperationKind::TokenLookup)
        else {
            continue;
        };
        let Some(final_write) = unit.operations.iter().rev().find(|operation| {
            operation.kind == OperationKind::Mutation && operation.line >= token_lookup.line
        }) else {
            continue;
        };

        let override_pattern = (final_write.text.contains("||")
            || final_write
                .text
                .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .any(|segment| segment.eq_ignore_ascii_case("or")))
            && final_write
                .subjects
                .iter()
                .any(|subject| subject.source_kind == ValueSourceKind::TokenField)
            && final_write
                .subjects
                .iter()
                .any(|subject| subject.source_kind != ValueSourceKind::TokenField);
        let has_expiry_check = unit
            .auth_checks
            .iter()
            .any(|check| check.kind == AuthCheckKind::TokenExpiry)
            || unit
                .condition_texts
                .iter()
                .any(|condition| rules.has_expiry_field(condition));
        let has_recipient_check = unit
            .auth_checks
            .iter()
            .any(|check| check.kind == AuthCheckKind::TokenRecipient)
            || unit
                .condition_texts
                .iter()
                .any(|condition| rules.has_recipient_field(condition));

        if override_pattern || !has_expiry_check || !has_recipient_check {
            let mut missing = Vec::new();
            if override_pattern {
                missing.push("request data overrides token-bound values");
            }
            if !has_expiry_check {
                missing.push("token expiration is not validated");
            }
            if !has_recipient_check {
                missing.push("token recipient identity is not validated");
            }
            findings.push(AuthFinding {
                rule_id: rules.rule_id("token_override_without_validation"),
                severity: Severity::High,
                span: final_write.span,
                message: format!(
                    "token acceptance flow writes through `{}` without validating that {}",
                    final_write.callee,
                    missing.join(", ")
                ),
            });
        }
    }

    findings
}

fn route_is_admin_sensitive(unit: &AnalysisUnit) -> bool {
    unit.call_sites.iter().any(|call| {
        let lower = call.name.to_ascii_lowercase();
        lower.contains("admin") || lower.contains("impersonat") || lower.contains("role")
    })
}

fn has_prior_subject_auth(
    unit: &AnalysisUnit,
    op: &SensitiveOperation,
    subjects: &[&ValueRef],
) -> bool {
    let relevant_checks = unit.auth_checks.iter().filter(|check| {
        check.line <= op.line
            && !matches!(
                check.kind,
                AuthCheckKind::LoginGuard
                    | AuthCheckKind::TokenExpiry
                    | AuthCheckKind::TokenRecipient
            )
    });

    relevant_checks.into_iter().any(|check| {
        subjects
            .iter()
            .any(|subject| auth_check_covers_subject(check, subject, unit))
    })
}

fn has_prior_collection_auth(
    unit: &AnalysisUnit,
    op: &SensitiveOperation,
    subjects: &[&ValueRef],
) -> bool {
    let relevant_checks = unit.auth_checks.iter().filter(|check| {
        check.line <= op.line
            && !matches!(
                check.kind,
                AuthCheckKind::LoginGuard
                    | AuthCheckKind::TokenExpiry
                    | AuthCheckKind::TokenRecipient
            )
    });

    relevant_checks.into_iter().any(|check| {
        subjects.iter().any(|subject| {
            check.subjects.iter().any(|check_subject| {
                check_subject.source_kind != ValueSourceKind::ArrayIndex
                    && canonical_subject_name(check_subject) == subject.name
            })
        })
    })
}

fn auth_check_covers_subject(check: &AuthCheck, subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    let subject_key = canonical_subject_name(subject);
    let subject_related_base = related_subject_base(subject);
    // A2 + B3: walk the row-binding chain from this subject so a
    // check subject naming any ancestor row covers downstream column
    // reads.  E.g. `group_id → row → rows`: a check on `rows` (the
    // SQL-authorized result var) covers the subject `group_id`.
    let subject_row_chain = row_binding_chain(unit, &subject.name);
    // B3: if any ancestor row is in the SQL-authorized set, every
    // ownership check materially covers this subject.  We model this
    // by treating the SQL synth check as covering whatever subject
    // names share an ancestor in `authorized_sql_vars`.
    let subject_anchor_authorized = subject_row_chain
        .iter()
        .any(|name| unit.authorized_sql_vars.contains(name));

    check.subjects.iter().any(|check_subject| {
        let check_key = canonical_subject_name(check_subject);
        let check_related_base = related_subject_base(check_subject);
        if check_key == subject_key
            || (subject_related_base.is_some() && subject_related_base == check_related_base)
            || (subject_related_base.as_ref() == Some(&check_key))
            || (check_related_base.as_ref() == Some(&subject_key))
        {
            return true;
        }
        for row in &subject_row_chain {
            if check_key == *row || check_related_base.as_deref() == Some(row.as_str()) {
                return true;
            }
        }
        // B3: SQL synth checks name the auth-gated row var directly.
        // If our subject's row chain leads into the same authorized
        // var family this check anchors to, accept the coverage.
        if subject_anchor_authorized && unit.authorized_sql_vars.contains(&check_key) {
            return true;
        }
        false
    })
}

/// Walk `unit.row_field_vars` transitively from `start` (inclusive)
/// to recover every ancestor row binding name.  Cycle-safe via a
/// visited set; depth-bounded at 16 hops to keep the worst case
/// trivial.  Returns a vec containing `start` followed by each
/// ancestor — empty when `start` is empty.
fn row_binding_chain(unit: &AnalysisUnit, start: &str) -> Vec<String> {
    let mut chain: Vec<String> = Vec::new();
    if start.is_empty() {
        return chain;
    }
    let mut cur = start.to_string();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut hops = 0;
    while hops < 16 && seen.insert(cur.clone()) {
        chain.push(cur.clone());
        let Some(next) = unit.row_field_vars.get(&cur) else {
            break;
        };
        cur = next.clone();
        hops += 1;
    }
    chain
}

fn canonical_subject_name(subject: &ValueRef) -> String {
    match subject.source_kind {
        ValueSourceKind::ArrayIndex => subject.base.clone().unwrap_or_else(|| subject.name.clone()),
        _ => subject.name.clone(),
    }
}

fn related_subject_base(subject: &ValueRef) -> Option<String> {
    let base = subject.base.as_deref()?;
    let lower = base.to_ascii_lowercase();
    if lower == "req"
        || lower.starts_with("req.")
        || lower == "request"
        || lower.starts_with("request.")
        || lower == "ctx"
        || lower.starts_with("ctx.")
        || lower == "session"
        || lower.starts_with("session.")
    {
        None
    } else {
        Some(base.to_string())
    }
}

fn is_relevant_target_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    is_id_like(subject)
        && !is_actor_context_subject(subject, unit)
        && !is_const_bound_subject(subject, unit)
        && !is_typed_bounded_subject(subject, unit)
}

/// True iff `subject` is a plain identifier whose declaration binds
/// it to a literal constant (`id := "id"`, `let userId = 1`, etc.).
/// Such bindings cannot be user-controlled and so must not be
/// classified as scoped-identifier subjects.  Only matches plain
/// `Identifier`-kind subjects (no base/field) — member chains like
/// `req.params.id` still pass through to the regular checks.
fn is_const_bound_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    if subject.base.is_some() || subject.field.is_some() {
        return false;
    }
    unit.const_bound_vars.contains(&subject.name)
}

/// True iff `subject` is a plain identifier that resolves to a
/// function parameter whose static type is a payload-incompatible
/// scalar (numeric or boolean — see [`super::apply_typed_bounded_params`]).
/// Spring `@PathVariable Long userId`, Axum `Path<i64>`, NestJS
/// `@Param('id') id: number`, and FastAPI `user_id: int` all qualify.
///
/// Phase 6: also matches member-access subjects like `dto.userId`
/// when `dto` is a typed-extractor parameter recognised by a Phase
/// 1-2 matcher AND the field's declared TypeKind is Int/Bool.
fn is_typed_bounded_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    if subject.base.is_none() && subject.field.is_none() {
        return unit.typed_bounded_vars.contains(&subject.name);
    }
    // Phase 6: member-access shape `base.field` whose `base` is a
    // typed-extractor parameter and whose field is declared as an
    // Int/Bool in the same-file DTO definition.  Per Hard Rule 3,
    // only fires when the base param itself was recognised by a
    // Phase 1-2 matcher — bare `dto.age` without a framework gate
    // never lifts.
    let Some(base) = subject.base.as_deref() else {
        return false;
    };
    let Some(field) = subject.field.as_deref() else {
        return false;
    };
    let root = base.split('.').next().unwrap_or(base);
    unit.typed_bounded_dto_fields
        .get(root)
        .is_some_and(|fields| fields.iter().any(|f| f == field))
}

fn is_actor_context_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
    if is_self_scoped_session_subject(subject) {
        return true;
    }

    // A3: `V.id`-shape subjects where `V` is bound from a login-guard /
    // auth-check call (or from a typed self-actor extractor parameter)
    // are the caller's own id. `V.group_id` / `V.workspace_id` stay
    // relevant — only self-identifier fields trip this branch, so
    // foreign scoped ids on the same actor binding still flag.
    if let Some(base) = subject.base.as_deref() {
        let root = base.split('.').next().unwrap_or(base);
        if unit.self_actor_vars.contains(root)
            && subject.field.as_deref().is_some_and(is_self_actor_id_field)
        {
            return true;
        }
    }

    // Transitive copy of `V.id`: `let uid = user.id; query(.., &[uid])`
    // — the subject `uid` is a plain identifier with no base/field, but
    // was recorded as a self-actor id copy at extract time.  Treat it
    // as actor context.
    if unit.self_actor_id_vars.contains(&subject.name) {
        return true;
    }

    matches!(
        subject_identity_key(subject).as_deref(),
        Some(
            "ownerid"
                | "authorid"
                | "actorid"
                | "currentuserid"
                | "uploaderid"
                | "createdby"
                | "updatedby"
        )
    )
}

fn is_self_actor_id_field(field: &str) -> bool {
    let lower = field.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "id" | "user_id" | "userid" | "uid"
            // Self-publish / self-channel fields: when the receiver
            // is bound from `require_auth(..)`, `user.email` /
            // `user.username` / `user.handle` reference the actor's
            // own identity (e.g. `realtime.publish_to_user(&user.email,
            // ...)` is a self-channel publish, not a foreign target).
            | "email" | "username" | "handle"
    )
}

fn subject_identity_key(subject: &ValueRef) -> Option<String> {
    let raw = match subject.source_kind {
        ValueSourceKind::ArrayIndex => subject.base.as_deref().unwrap_or(&subject.name),
        _ => subject
            .field
            .as_deref()
            .or(subject.base.as_deref())
            .unwrap_or(&subject.name),
    };
    let key: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if key.is_empty() { None } else { Some(key) }
}

fn is_self_scoped_session_subject(subject: &ValueRef) -> bool {
    subject.source_kind == ValueSourceKind::Session
        && subject
            .base
            .as_deref()
            .is_some_and(is_self_scoped_session_base)
}

fn is_self_scoped_session_base(base: &str) -> bool {
    matches!(
        base,
        "req.session.user"
            | "request.session.user"
            | "session.user"
            | "req.session.currentUser"
            | "request.session.currentUser"
            | "session.currentUser"
            | "req.user"
            | "request.user"
            | "req.currentUser"
            | "request.currentUser"
            | "ctx.session.user"
            | "ctx.session.currentUser"
            | "ctx.state.user"
            | "ctx.state.currentUser"
    )
}

fn is_stale_session_subject(subject: &ValueRef) -> bool {
    subject.source_kind == ValueSourceKind::Session
        && is_id_like(subject)
        && !is_self_scoped_session_subject(subject)
}

fn unit_is_auth_helper(unit: &AnalysisUnit) -> bool {
    let Some(name) = unit.name.as_deref() else {
        return false;
    };
    let normalized: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (normalized.starts_with("has")
        || normalized.starts_with("check")
        || normalized.starts_with("require")
        || normalized.starts_with("verify")
        || normalized.starts_with("authorize")
        || normalized.starts_with("can")
        || normalized.starts_with("is"))
        && (normalized.contains("membership")
            || normalized.contains("ownership")
            || normalized.contains("access")
            || normalized.contains("permission")
            || normalized.contains("authoriz"))
}

fn is_delegated_read_with_actor_context(
    unit: &AnalysisUnit,
    op: &SensitiveOperation,
    relevant_subjects: &[&ValueRef],
) -> bool {
    unit.kind == super::model::AnalysisUnitKind::RouteHandler
        && op.kind == OperationKind::Read
        && op.callee.to_ascii_lowercase().contains("service")
        && op.subjects.iter().any(is_self_scoped_session_subject)
        && relevant_subjects.iter().any(|subject| {
            matches!(
                subject.source_kind,
                ValueSourceKind::RequestParam
                    | ValueSourceKind::RequestBody
                    | ValueSourceKind::RequestQuery
            )
        })
}

fn is_id_like(subject: &ValueRef) -> bool {
    let field = subject
        .field
        .as_deref()
        .or(subject.base.as_deref())
        .unwrap_or(&subject.name);
    let lower = field.to_ascii_lowercase();
    lower == "id"
        || lower.ends_with("id")
        || lower.ends_with("_id")
        || lower.ends_with("ids")
        || lower.contains("workspaceid")
        || lower.contains("projectid")
        || lower.contains("noteid")
}

fn is_batch_collection(subject: &ValueRef) -> bool {
    subject.source_kind == ValueSourceKind::Identifier
        && subject.name.to_ascii_lowercase().ends_with("ids")
}

#[cfg(test)]
mod tests {
    use super::{is_actor_context_subject, is_relevant_target_subject};
    use crate::auth_analysis::model::{AnalysisUnit, AnalysisUnitKind, ValueRef, ValueSourceKind};
    use std::collections::{HashMap, HashSet};

    fn empty_unit() -> AnalysisUnit {
        AnalysisUnit {
            kind: AnalysisUnitKind::Function,
            name: Some("handle".into()),
            span: (0, 0),
            params: Vec::new(),
            context_inputs: Vec::new(),
            call_sites: Vec::new(),
            auth_checks: Vec::new(),
            operations: Vec::new(),
            value_refs: Vec::new(),
            condition_texts: Vec::new(),
            line: 1,
            row_field_vars: HashMap::new(),
            self_actor_vars: HashSet::new(),
            self_actor_id_vars: HashSet::new(),
            authorized_sql_vars: HashSet::new(),
            const_bound_vars: HashSet::new(),
            typed_bounded_vars: HashSet::new(),
            typed_bounded_dto_fields: HashMap::new(),
        }
    }

    fn member(base: &str, field: &str) -> ValueRef {
        ValueRef {
            source_kind: ValueSourceKind::MemberField,
            name: format!("{base}.{field}"),
            base: Some(base.to_string()),
            field: Some(field.to_string()),
            index: None,
            span: (0, 0),
        }
    }

    #[test]
    fn self_actor_var_widens_actor_context_for_self_id_fields() {
        let mut unit = empty_unit();
        unit.self_actor_vars.insert("user".into());

        // `user.id`-shape subjects count as actor context now.
        assert!(is_actor_context_subject(&member("user", "id"), &unit));
        assert!(is_actor_context_subject(&member("user", "user_id"), &unit));
        assert!(is_actor_context_subject(&member("user", "uid"), &unit));

        // Pitfall guard: `user.group_id` / `user.workspace_id` stay
        // relevant — only self-identifier fields trip the widening.
        assert!(!is_actor_context_subject(
            &member("user", "group_id"),
            &unit
        ));
        assert!(!is_actor_context_subject(
            &member("user", "workspace_id"),
            &unit
        ));

        // Variables not in self_actor_vars fall back to the existing
        // identity-key match — `target.id` still flags.
        assert!(!is_actor_context_subject(&member("target", "id"), &unit));
    }

    #[test]
    fn self_actor_var_suppresses_relevant_subject_for_self_id() {
        let mut unit = empty_unit();
        unit.self_actor_vars.insert("user".into());

        assert!(!is_relevant_target_subject(&member("user", "id"), &unit));
        // Foreign id on the same actor binding still matters.
        assert!(is_relevant_target_subject(
            &member("user", "group_id"),
            &unit
        ));
    }

    fn plain(name: &str) -> ValueRef {
        ValueRef {
            source_kind: ValueSourceKind::Identifier,
            name: name.to_string(),
            base: None,
            field: None,
            index: None,
            span: (0, 0),
        }
    }

    /// Real-repo regression: `let uid = user.id; query(.., &[uid])`.
    /// `uid` lives in `self_actor_id_vars` and the subject `uid`
    /// (plain Local, no base/field) must count as actor context.
    #[test]
    fn self_actor_id_vars_widens_actor_context_for_plain_subjects() {
        let mut unit = empty_unit();
        unit.self_actor_id_vars.insert("uid".into());

        // `uid` plain subject is recognised as actor context.
        assert!(is_actor_context_subject(&plain("uid"), &unit));
        // Plain identifiers NOT in the set still flag.
        assert!(!is_actor_context_subject(&plain("trip_id"), &unit));
        assert!(!is_actor_context_subject(&plain("doc_id"), &unit));
    }

    /// Self-publish identity fields: `&user.email` /
    /// `&user.username` / `&user.handle` for a self-actor must be
    /// recognised as actor context (real-repo `realtime::publish_to_user`
    /// shape).
    #[test]
    fn self_actor_id_field_set_includes_email_username_handle() {
        let mut unit = empty_unit();
        unit.self_actor_vars.insert("user".into());

        assert!(is_actor_context_subject(&member("user", "email"), &unit));
        assert!(is_actor_context_subject(&member("user", "username"), &unit));
        assert!(is_actor_context_subject(&member("user", "handle"), &unit));

        // Foreign-user fields still flag.
        assert!(!is_actor_context_subject(&member("target", "email"), &unit));
    }

    /// Real-repo regression (gin/context_test.go): `id := "id";
    /// c.AddParam(id, value)` previously fired the rule because `id`
    /// matched is_id_like but had no actor-context exemption.  After
    /// the const-binding tracker, `id` (a plain Local with no base /
    /// field) bound to a literal is excluded from relevant subjects.
    #[test]
    fn const_bound_plain_subjects_are_not_relevant() {
        let mut unit = empty_unit();
        unit.const_bound_vars.insert("id".into());

        // `id` matches is_id_like (name=="id") but is constant-bound.
        assert!(!is_relevant_target_subject(&plain("id"), &unit));

        // Plain `id` NOT in the const-bound set still flags as
        // relevant — regression guard for the user-controlled case.
        let unit2 = empty_unit();
        assert!(is_relevant_target_subject(&plain("id"), &unit2));

        // Member access `req.id` is unaffected by const-bound check
        // (different ValueRef shape).
        unit.const_bound_vars.insert("req".into());
        assert!(is_relevant_target_subject(&member("req", "id"), &unit));
    }

    /// Phase 5 typed-bounded subject exclusion: a parameter whose
    /// static type was recovered as `Int`/`Bool` (Spring `Long userId`,
    /// Axum `Path<i64>`, FastAPI `user_id: int`) has its name added to
    /// `unit.typed_bounded_vars` by `apply_typed_bounded_params`.  The
    /// subject `userId` then must not be classified as a scoped
    /// identifier — the framework guarantees the value is numeric and
    /// cannot drive ownership-bypass.
    #[test]
    fn typed_bounded_plain_subjects_are_not_relevant() {
        let mut unit = empty_unit();
        unit.typed_bounded_vars.insert("user_id".into());

        // `user_id` matches is_id_like but is bounded by static type.
        assert!(!is_relevant_target_subject(&plain("user_id"), &unit));

        // Plain `user_id` NOT in the typed-bounded set still flags.
        let unit2 = empty_unit();
        assert!(is_relevant_target_subject(&plain("user_id"), &unit2));

        // Member access `req.user_id` is unaffected (only plain
        // identifiers are exempted — fields/base remain regular
        // subjects so DTO-shape leaks still flag).
        unit.typed_bounded_vars.insert("req".into());
        assert!(is_relevant_target_subject(&member("req", "user_id"), &unit));
    }
}
