// Phase 8.3 regression: a tainted env string is pushed into an array
// and later read back via subscript before being sunk through
// child_process.exec.  This exercises container-element taint.
const items = [];
items.push(process.env.INPUT);
require('child_process').exec(items[0]);
