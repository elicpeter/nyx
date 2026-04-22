var express = require('express');
var app = express();

// Ternary where the true branch carries tainted data. The decomposition must
// still fire the sink: the phi at the join unions the tainted branch's value
// with the literal fallback, yielding a tainted phi result at res.send.
app.get('/echo', function(req, res) {
    var name = req.query.name;
    var preferFull = req.query.mode;
    var out = preferFull
        ? '<p>hello, ' + name + '</p>'
        : '<p>hello, anonymous</p>';
    res.send(out);
});
