// Closure captures a tainted outer var and is called later in same scope.
// Expected: sink triggers on req.query.q → eval inside closure.
var express = require('express');
var app = express();

app.get('/a', function(req, res) {
    var q = req.query.q;                 // source
    var fn = function() { eval(q); };   // closure captures q
    fn();                                // invoke captured closure
    res.send('ok');
});
