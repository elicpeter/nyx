const { exec } = require('child_process');

/**
 * ADVERSARIAL — same-file identity collision.
 *
 * This file defines multiple entities that share the leaf name
 * `runTask` with different containers and different security
 * behaviours.  The resolver must not confuse them.
 */

// ── Free function: SHELL-EXEC sink ──────────────────────────────────
// Bare `runTask(t)` calls (no receiver, no qualifier) MUST target
// this free function.  Regression guard: before the bare-call
// free-function preference was added, same-file resolution returned
// Ambiguous whenever another container also defined `runTask`, and
// the SHELL_ESCAPE sink was silently lost.
function runTask(cmd) {
    exec(cmd);
}

// ── Class method: harmless passthrough ──────────────────────────────
// Shares the leaf `runTask` to create an identity collision inside
// the same file.  Must NOT be picked up by bare-call resolution even
// though `NotifyQueue::runTask` matches the leaf name + arity.
class NotifyQueue {
    runTask(message) {
        return '[notify] ' + message;
    }
}

// ── Another class method: distinct SHELL-EXEC sink ──────────────────
// Two classes with the same method name `runTask`.  When invoked via
// an instance variable the resolver cannot tell them apart without
// type inference — it must refuse to pick one silently.
class CommandRunner {
    runTask(cmd) {
        exec(cmd);
    }
}

class SilentWorker {
    runTask(msg) {
        return msg.trim();
    }
}

// ── Caller 1: bare top-level call → free function ───────────────────
// `runTask` has no receiver, no qualifier.  The resolver must pick
// the free function (SHELL sink) — not a method.  Expected finding:
// taint-unsanitised-flow (SHELL_ESCAPE).
function handleBare(req) {
    const tainted = req.query.q;    // Express source
    runTask(tainted);               // SINK via free function
}

// ── Caller 2: method call on explicitly-named class instance ────────
// `new SilentWorker().runTask(tainted)` is syntactically a method
// call — MUST NOT be silently resolved to the free function.  The
// SilentWorker method is harmless, so no sink finding is expected.
function handleSafeMethod(req) {
    const tainted = req.query.q;
    const w = new SilentWorker();
    w.runTask(tainted);
}

module.exports = { handleBare, handleSafeMethod, NotifyQueue, CommandRunner, SilentWorker };
