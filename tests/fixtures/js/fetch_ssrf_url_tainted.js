// SSRF regression fixture: attacker-controlled destination URL.  SSRF must
// fire on the URL flow (arg 0) and `Cap::DATA_EXFIL` must NOT fire — the two
// classes share the callee but cap attribution is per-position so a tainted
// URL never surfaces as data exfiltration.
//
// Driven by `fetch_data_exfil_integration_tests.rs`.
function proxy(req) {
    var target = req.query.target;
    fetch(target);
}
