// FP GUARD — cross-call-site specialization (JS: safe caller only).
//
// `runQuery` is a helper that forwards its second arg to db.query.
// k=1 inline analysis means the caller-site cap signature dictates
// whether the callee's internal sink surfaces as a flow.
// Here the only caller passes a compile-time-constant string, so no
// finding may fire — even if elsewhere in the same codebase another
// caller of `runQuery` sends tainted data (that case lives in
// `call_site_specialization_py`).
//
// Expected: NO taint-unsanitised-flow finding.

function runQuery(db, q) {
    return db.query(q);
}

function safeOnly(db) {
    return runQuery(db, "SELECT COUNT(*) FROM users");
}

module.exports = { safeOnly };
