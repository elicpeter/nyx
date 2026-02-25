/**
 EXPECTED OUTPUT (high-level):

 1) cfg-unguarded-sink (High / High confidence)
 - handler(req,res): source req.body.cmd flows to child_process.exec(cmd) without sanitizer/guard.
 - Should rank high (entry-point-ish function name 'handler', close to entry).

 2) cfg-auth-gap (High / Medium)
 - handler is entry-point-ish (name matches handler/route/api conventions).
 - No auth guard dominates sink (require_auth / is_authenticated / is_admin / authorize).

 3) cfg-error-fallthrough (Medium / Medium)
 - Example: if (err) { console.log(err); } then exec(...) still runs.
 - This is the JS analogue of your Go heuristic. If your implementation only targets Go, this should be NO finding.
 If you later generalize, this file includes a pattern you can test against.

 4) cfg-unguarded-sink (HTML) (Medium/High)
 - req.query.html is written into innerHTML without DOMPurify.sanitize

 5) No findings for safe paths:
 - safeHandler uses encodeURIComponent before exec (URL_ENCODE sanitizer) OR uses a dedicated sanitizer you map to SHELL_ESCAPE.
 NOTE: encodeURIComponent is URL_ENCODE, not SHELL_ESCAPE — so for SHELL_ESCAPE sinks, it may still be flagged depending on your caps logic.
 The “definitely safe” case here uses a dummy sanitize_shell() wrapper to match your Rust-style naming if you add it for JS later.
 - safeHtml uses DOMPurify.sanitize before innerHTML (HTML_ESCAPE).

 Taint / dataflow:
 - should find taint from req.body / req.query / process.env sources to exec/eval/innerHTML sinks.
 */

const child_process = require("child_process");

// ─── Entry-point-ish + unguarded shell sink + auth gap ────────────────────────────
function handler(req, res) {
    // Source (Cap::all): req.body
    const cmd = req.body.cmd;

    // Vulnerable sink (Cap::SHELL_ESCAPE): child_process.exec
    child_process.exec(cmd);

    res.end("ok");
}

// ─── Guarded HTML sink (should NOT be flagged) ────────────────────────────────────
function safeHtml(req, res, DOMPurify) {
    const html = req.query.html; // Source
    const cleaned = DOMPurify.sanitize(html); // Sanitizer(HTML_ESCAPE)
    document.getElementById("app").innerHTML = cleaned; // Sink(HTML_ESCAPE)
    res.end("ok");
}

// ─── Unguarded HTML sink (should be flagged) ─────────────────────────────────────
function unsafeHtml(req, res) {
    const html = req.query.html; // Source
    document.getElementById("app").innerHTML = html; // Sink(HTML_ESCAPE) without sanitizer
    res.end("ok");
}

// ─── Heuristic error fallthrough pattern (JS analogue) ───────────────────────────
// If your error-handling analysis is Go-only, ignore this for now.
// If generalized later, it should be flagged.
function errFallthrough(req, res) {
    const err = req.query.err;
    if (err) {
        console.log(err);
    }
    child_process.exec(req.body.cmd);
    res.end("ok");
}

// ─── Optional: eval sink (should be flagged) ─────────────────────────────────────
function evalSink(req) {
    const payload = process.env.PAYLOAD; // Source
    eval(payload); // Sink(SHELL_ESCAPE) per your rules
}