// Local function — generates summary: propagating_params=[0]
function passthrough(x) {
    return x;
}

var express = require('express');
var app = express();

// Case 1: zero-arg method call — tests the emptiness-check fix.
// arg_uses=[["tainted"]] (receiver only), real_arg_count=0 → fallback to
// collect_uses_taint → receiver taint propagates.
app.get('/a', function(req, res) {
    var tainted = req.query.data;
    var result = tainted.passthrough();
    res.send(result);
});

// Case 2: method call with args — tests offset correctness.
// arg_uses=[["tainted"],[] ], param 0 + offset 1 → [] → not tainted.
// Receiver not referenced by summary → no propagation. No finding expected.
app.get('/b', function(req, res) {
    var tainted = req.query.data;
    var result = tainted.passthrough("safe");
    res.send(result);
});
