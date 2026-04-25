// FP GUARD — struct-field isolation (JS nested object).
//
// A deeply nested path (`cfg.auth.userName`) is populated with
// tainted data, while a sibling path (`cfg.auth.template`) is a
// constant.  The sink consumes only the sibling.  An analysis that
// only distinguishes top-level objects would spuriously flag this.
//
// Expected: NO taint-unsanitised-flow finding.

const { exec } = require("child_process");

function trigger(req) {
    const cfg = {
        auth: {
            userName: req.query.name,       // taint
            template: "/usr/bin/whoami",    // constant
        },
    };
    exec(cfg.auth.template);                 // constant only
}

module.exports = { trigger };
