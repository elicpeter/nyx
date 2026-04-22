// Cross-file callback-sink tracking.  `apply` lives in apply.js; the
// caller passes `child_process.exec` directly as the callback, so the
// callback-argument mechanism in the caller's transfer_inst pairs
// `apply`'s (cross-file) summary with the labelled-sink callback and
// surfaces the taint flow.  Cross-file inline must not interfere
// with this path.

const { apply } = require('./apply');
const child_process = require('child_process');

function main() {
    const envValue = process.env.USER_CMD;
    const result = apply(child_process.exec, envValue);
    return result;
}

main();
