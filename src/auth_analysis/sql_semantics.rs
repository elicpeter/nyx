//! SQL literal semantics.
//!
//! A focused, lightweight SQL detector that classifies a literal SQL
//! query as **authorization-gated** when one of two patterns holds:
//!
//! 1. **JOIN-through-ACL**: `SELECT … FROM <T> JOIN <ACL> ON … WHERE
//!    <ACL>.user_id = ?N` where `<ACL>` is in the configured ACL-table
//!    list (`group_members`, `org_memberships`, …). The JOIN proves
//!    that every returned row belongs to a tenant the bound `?N` user
//!    is a member of.
//!
//! 2. **Direct ownership**: `WHERE … user_id = ?N` (with optional
//!    additional predicates like `WHERE id = ?M AND user_id = ?N`).
//!    The `user_id = ?N` predicate proves every returned row is owned
//!    by the bound user.
//!
//! Detection is conservative: ambiguous shapes return `None`, and the
//! caller (in `extract::common::collect_row_population`) only synthesizes
//! an `AuthCheck` when classification is positive. False negatives
//! (missing real auth) are safe; false positives (spuriously claiming
//! auth) are not.
//!
//! No SQL parser dependency: the rules below operate on lower-cased
//! whitespace-normalised text and pattern-match the relevant clauses.

/// Classification of a literal SQL query for authorization purposes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlAuthClassification {
    /// Query is auth-gated. The JOIN (or direct WHERE) pins returned
    /// rows to the bound user. We don't track *which* bind position
    /// here, the caller treats whichever bind value flows into the
    /// query as the user-id witness; that's safe because the caller
    /// already requires the row binding to come from a `let X = …`
    /// site we can name.
    Authorized,
}

/// Classify `sql` as auth-gated under the configured ACL tables.
/// Returns `Some(Authorized)` when one of the recognized patterns
/// holds, `None` otherwise (conservative, unknown shapes are treated
/// as unauthorized).
pub fn classify_sql_query(sql: &str, acl_tables: &[String]) -> Option<SqlAuthClassification> {
    let normalized = normalize_sql(sql);
    if !normalized.trim_start().starts_with("select") {
        // For B3 we only authorize SELECT queries, INSERT/UPDATE/DELETE
        // need their own analysis and aren't in scope. (A literal
        // `DELETE … WHERE user_id = ?N` could be safely authorized,
        // but the call sites we care about for FP suppression are
        // reads.)
        return None;
    }

    if matches_join_through_acl(&normalized, acl_tables) {
        return Some(SqlAuthClassification::Authorized);
    }
    if matches_direct_user_id_predicate(&normalized) {
        return Some(SqlAuthClassification::Authorized);
    }
    None
}

/// `SELECT … FROM <T> [AS] <ALIAS>? JOIN <ACL> [AS] <GA>? ON … WHERE
/// <GA?>.user_id = ?N`, verifies that an ACL table appears in a JOIN
/// clause and that the WHERE clause contains a `<…>.user_id = ?` (or
/// bare `user_id = ?`) predicate.  Order of the WHERE predicates
/// doesn't matter; AND/OR connectors are ignored.
fn matches_join_through_acl(sql: &str, acl_tables: &[String]) -> bool {
    let Some(where_idx) = sql.find(" where ") else {
        return false;
    };
    let from_to_where = &sql[..where_idx];
    let where_clause = &sql[where_idx + " where ".len()..];

    let has_acl_join = acl_tables.iter().any(|t| {
        let lower = t.to_ascii_lowercase();
        // " join <acl>" or " join <acl> "
        from_to_where.contains(&format!(" join {} ", lower))
            || from_to_where.ends_with(&format!(" join {}", lower))
            || from_to_where.contains(&format!(" inner join {} ", lower))
            || from_to_where.contains(&format!(" left join {} ", lower))
            || from_to_where.contains(&format!(" right join {} ", lower))
    });
    if !has_acl_join {
        return false;
    }

    where_clause_contains_user_id_bind(where_clause)
}

/// Direct ownership: `SELECT … FROM <T> WHERE … user_id = ?N`, no
/// JOIN.  Covers single-table reads where the row already carries the
/// owning user id (`SELECT … FROM docs WHERE user_id = ?1`).  We do
/// NOT require `id = ?M` to also be present; the `user_id = ?N`
/// predicate alone is sufficient, since any row returned must be
/// owned by the bound user.
///
/// Refuses to fire when a JOIN is present, the JOIN target may not
/// be in the ACL list, so the WHERE predicate (which may apply to
/// the joined table, e.g. `WHERE al.user_id = ?N` against an
/// `audit_log` JOIN) doesn't actually pin the primary rows to the
/// caller.  The JOIN-through-ACL path handles those cases explicitly.
fn matches_direct_user_id_predicate(sql: &str) -> bool {
    let Some(where_idx) = sql.find(" where ") else {
        return false;
    };
    let from_to_where = &sql[..where_idx];
    if from_to_where.contains(" join ") {
        return false;
    }
    let where_clause = &sql[where_idx + " where ".len()..];
    where_clause_contains_user_id_bind(where_clause)
}

/// Does the WHERE clause contain `<table?>.user_id = ?<digits>` (or
/// `<table?>.user_id = $<digits>` for postgres-style placeholders, or
/// `<table?>.user_id = :name` for named binds)?  The optional table
/// qualifier handles `gm.user_id` (alias-qualified) and bare `user_id`.
fn where_clause_contains_user_id_bind(where_clause: &str) -> bool {
    // Strip ORDER BY / LIMIT / GROUP BY / HAVING tails so we don't
    // hunt past the WHERE clause for a `user_id = ?` that isn't
    // actually a predicate.
    let where_only = strip_trailing_clauses(where_clause);
    let needles = ["user_id", "userid"];
    for needle in needles {
        for (idx, _) in where_only.match_indices(needle) {
            // Make sure this is a column boundary on the left side
            // (avoid matching `posted_user_id` or `target_user_id`
            //, those don't pin to the actor).
            let before = where_only[..idx].chars().last();
            if !is_column_boundary_left(before) {
                continue;
            }
            // Skip past `user_id`. Trim whitespace then look for `=`.
            let rest = &where_only[idx + needle.len()..];
            let rest = rest.trim_start();
            if !rest.starts_with('=') {
                continue;
            }
            let after_eq = rest[1..].trim_start();
            if looks_like_bind_param(after_eq) {
                return true;
            }
        }
    }
    false
}

fn is_column_boundary_left(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(c) => matches!(c, ' ' | '\t' | '(' | '.' | ',' | '\n' | '\r'),
    }
}

fn looks_like_bind_param(after_eq: &str) -> bool {
    let bytes = after_eq.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    match bytes[0] {
        // ?N (sqlite/sqlx anonymous), accept ?, ?1, ?2…
        b'?' => true,
        // $N (postgres style), require a digit after.
        b'$' => bytes.get(1).is_some_and(|b| b.is_ascii_digit()),
        // :name (named bind), require an identifier char after.
        b':' => bytes
            .get(1)
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_'),
        _ => false,
    }
}

/// Cut off ORDER BY / LIMIT / GROUP BY / HAVING tails so the WHERE
/// scan stays inside the predicate region.
fn strip_trailing_clauses(where_clause: &str) -> &str {
    let candidates = [" order by ", " limit ", " group by ", " having "];
    let mut end = where_clause.len();
    for cand in candidates {
        if let Some(idx) = where_clause.find(cand) {
            end = end.min(idx);
        }
    }
    &where_clause[..end]
}

/// Lower-case + collapse whitespace + flatten line breaks so the
/// patterns above can use single-space tokens.
fn normalize_sql(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    let mut prev_space = true;
    // Surround with leading/trailing space so " where " etc. searches
    // hit boundary cases at the very start/end.
    out.push(' ');
    for ch in sql.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch.to_ascii_lowercase());
            prev_space = false;
        }
    }
    if !out.ends_with(' ') {
        out.push(' ');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{SqlAuthClassification, classify_sql_query};

    fn acl() -> Vec<String> {
        vec![
            "group_members".into(),
            "org_memberships".into(),
            "workspace_members".into(),
            "tenant_members".into(),
            "members".into(),
            "share_grants".into(),
        ]
    }

    #[test]
    fn join_through_group_members_with_user_bind_is_authorized() {
        let sql = "SELECT d.id, d.group_id, d.title \
                   FROM docs d \
                   JOIN group_members gm ON gm.group_id = d.group_id \
                   WHERE gm.user_id = ?1 \
                   ORDER BY d.updated_at DESC";
        assert_eq!(
            classify_sql_query(sql, &acl()),
            Some(SqlAuthClassification::Authorized)
        );
    }

    #[test]
    fn join_through_workspace_members_with_postgres_bind() {
        let sql = "SELECT t.* \
                   FROM tickets t \
                   INNER JOIN workspace_members wm ON wm.workspace_id = t.workspace_id \
                   WHERE wm.user_id = $1";
        assert_eq!(
            classify_sql_query(sql, &acl()),
            Some(SqlAuthClassification::Authorized)
        );
    }

    #[test]
    fn direct_user_id_predicate_is_authorized() {
        let sql = "SELECT id, name FROM peers WHERE user_id = ?1";
        assert_eq!(
            classify_sql_query(sql, &acl()),
            Some(SqlAuthClassification::Authorized)
        );
    }

    #[test]
    fn direct_id_and_user_id_predicate_is_authorized() {
        let sql = "SELECT title FROM docs WHERE id = ?1 AND user_id = ?2";
        assert_eq!(
            classify_sql_query(sql, &acl()),
            Some(SqlAuthClassification::Authorized)
        );
    }

    #[test]
    fn named_bind_is_authorized() {
        let sql = "SELECT * FROM peers WHERE user_id = :uid";
        assert_eq!(
            classify_sql_query(sql, &acl()),
            Some(SqlAuthClassification::Authorized)
        );
    }

    #[test]
    fn join_against_non_acl_table_is_not_authorized() {
        // `audit_log` is not in the configured ACL list, JOIN doesn't
        // pin rows to the bound user, so the query is unauthorized.
        let sql = "SELECT d.* FROM docs d \
                   JOIN audit_log al ON al.doc_id = d.id \
                   WHERE al.user_id = ?1";
        assert_eq!(classify_sql_query(sql, &acl()), None);
    }

    #[test]
    fn select_without_user_id_predicate_is_not_authorized() {
        let sql = "SELECT * FROM docs WHERE id = ?1";
        assert_eq!(classify_sql_query(sql, &acl()), None);
    }

    #[test]
    fn non_select_query_is_not_authorized() {
        // INSERT/UPDATE/DELETE are not in scope for B3 even when the
        // WHERE clause names the user.
        let sql = "DELETE FROM docs WHERE user_id = ?1";
        assert_eq!(classify_sql_query(sql, &acl()), None);
    }

    #[test]
    fn similar_column_names_do_not_trip_user_id_match() {
        // `posted_user_id` shouldn't satisfy the `user_id = ?` check ,
        // that column doesn't pin to the actor.
        let sql = "SELECT * FROM posts WHERE posted_user_id = ?1";
        assert_eq!(classify_sql_query(sql, &acl()), None);
    }

    #[test]
    fn order_by_after_user_id_is_handled() {
        let sql = "SELECT * FROM peers WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 50";
        assert_eq!(
            classify_sql_query(sql, &acl()),
            Some(SqlAuthClassification::Authorized)
        );
    }

    #[test]
    fn empty_acl_list_disables_join_pattern_but_keeps_direct() {
        let join_sql = "SELECT * FROM docs d \
                        JOIN group_members gm ON gm.group_id = d.group_id \
                        WHERE gm.user_id = ?1";
        let direct_sql = "SELECT * FROM peers WHERE user_id = ?1";
        let empty: Vec<String> = Vec::new();
        // No ACL configured → join pattern can't fire, but direct
        // predicate still authorizes.
        assert_eq!(classify_sql_query(join_sql, &empty), None);
        assert_eq!(
            classify_sql_query(direct_sql, &empty),
            Some(SqlAuthClassification::Authorized)
        );
    }
}
