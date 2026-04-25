var express = require('express');
var app = express();

// Test: dynamic (non-constant) index falls back to Elements.
// Should conservatively report taint since the index is unknown.
app.get('/dyn', function(req, res) {
    var m = new Map();
    m.set(0, req.query.input);
    var idx = parseInt(req.query.idx);
    var val = m.get(idx);
    res.send(val); // dynamic index → Elements → sees taint — SHOULD flag
});
