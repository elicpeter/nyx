// Phase 8.1 regression: an arrow function captures a tainted variable
// from its enclosing scope and later sinks it via child_process.exec.
//
// The engine must follow the closure boundary — i.e. recognise that the
// inner arrow references `tainted` from `makeHandler` — and surface a
// taint-unsanitised-flow finding from env to exec.
function makeHandler() {
    const tainted = process.env.USER_INPUT;
    return (req) => {
        require('child_process').exec(tainted);
    };
}

const h = makeHandler();
h({});

module.exports = { makeHandler };
