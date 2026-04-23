// Regression fixture: promise-chain taint flow.  The env var read
// inside a `.then(...)` callback is concatenated with fetched text and
// forwarded through two more `.then` stages before being sunk via
// `child_process.exec`.
//
// Intended finding: taint-unsanitised-flow from process.env.PREFIX to
// the exec sink.  The engine must follow taint across the chained
// promise callbacks — a per-callback analysis is not enough on its own
// because the tainted value is defined in one arrow and sunk in
// another.
fetch('/api')
    .then(res => res.text())
    .then(text => process.env.PREFIX + text)
    .then(combined => require('child_process').exec(combined));
