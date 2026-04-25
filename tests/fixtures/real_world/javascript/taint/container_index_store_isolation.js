var express = require('express');
var app = express();

// Test: constant-index store isolation.
// Taint stored at index 0 should not pollute index 1.
app.get('/idx', function(req, res) {
    var m = new Map();
    m.set(0, req.query.input);
    m.set(1, "safe_value");
    res.send(m.get(1)); // index 1 is safe — should NOT flag
});
