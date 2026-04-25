// Arrow function assigned to object property (NOT a declaration).
// An assignment_expression parents the arrow_function — possible blind spot.
var express = require('express');
var app = express();
var handlers = {};

app.get('/a', function(req, res) {
    var q = req.query.q;
    handlers.run = function() { eval(q); };  // assignment-expression path
    handlers.run();
    res.send('ok');
});
