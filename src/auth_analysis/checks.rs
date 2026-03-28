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
    findings.extend(check_ownership_gaps(model));
    findings.extend(check_partial_batch_authorization(model));
    findings.extend(check_stale_authorization(model));
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
                rule_id: "js.auth.admin_route_missing_admin_check".into(),
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

fn check_ownership_gaps(model: &AuthorizationModel) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        for op in &unit.operations {
            if op.kind == OperationKind::TokenLookup {
                continue;
            }
            let relevant_subjects: Vec<&ValueRef> =
                op.subjects.iter().filter(|s| is_id_like(s)).collect();
            if relevant_subjects.is_empty() {
                continue;
            }
            if op.kind == OperationKind::Read || op.kind == OperationKind::Mutation {
                if !has_prior_subject_auth(unit, op, &relevant_subjects) {
                    findings.push(AuthFinding {
                        rule_id: "js.auth.missing_ownership_check".into(),
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

fn check_partial_batch_authorization(model: &AuthorizationModel) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        for op in &unit.operations {
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

            if partial_check {
                findings.push(AuthFinding {
                    rule_id: "js.auth.partial_batch_authorization".into(),
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

fn check_stale_authorization(model: &AuthorizationModel) -> Vec<AuthFinding> {
    let mut findings = Vec::new();

    for unit in &model.units {
        for op in unit
            .operations
            .iter()
            .filter(|operation| operation.kind == OperationKind::Mutation)
        {
            let session_subject = op.subjects.iter().any(|subject| {
                subject.source_kind == ValueSourceKind::Session && is_id_like(subject)
            });
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
                    rule_id: "js.auth.stale_authorization".into(),
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

        let override_pattern = final_write.text.contains("||")
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
                rule_id: "js.auth.token_override_without_validation".into(),
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
    unit.operations.iter().any(|operation| {
        let lower = operation.callee.to_ascii_lowercase();
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
            .any(|subject| auth_check_covers_subject(check, subject))
    })
}

fn auth_check_covers_subject(check: &AuthCheck, subject: &ValueRef) -> bool {
    let subject_key = canonical_subject_name(subject);
    check
        .subjects
        .iter()
        .map(canonical_subject_name)
        .any(|check_key| check_key == subject_key)
}

fn canonical_subject_name(subject: &ValueRef) -> String {
    match subject.source_kind {
        ValueSourceKind::ArrayIndex => subject.base.clone().unwrap_or_else(|| subject.name.clone()),
        _ => subject.name.clone(),
    }
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
