// FP GUARD — struct-field isolation (JS object fields).
//
// `obj.unsafeField` is assigned a tainted value; `obj.safeField` is a
// hardcoded string.  Only `obj.safeField` flows to the sink.  A
// field-precise analysis must not treat `obj` as a monolithic tainted
// bag — the SQL query is built solely from the hardcoded field.
//
// Expected: NO taint-unsanitised-flow finding.

function buildQuery(req, db) {
    const obj = {
        safeField: "SELECT 1",
        unsafeField: req.query.cmd,        // taint lands here
    };
    return db.query(obj.safeField);         // only the constant reaches the sink
}

module.exports = { buildQuery };
