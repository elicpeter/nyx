var express = require('express');
var app = express();

// Test: constant-index load precision.
// Only the tainted index should flow to the sink.
app.get('/idx', function(req, res) {
    var m = new Map();
    m.set(0, req.query.input);
    m.set(1, "safe");
    var y = m.get(0);
    res.send(y); // index 0 is tainted — SHOULD flag
});
