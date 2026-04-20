// Three-level nested closures; innermost sinks a capture from the outermost.
var express = require('express');
var app = express();

app.get('/a', function(req, res) {
    var q = req.query.q;
    setTimeout(function() {
        setImmediate(function() {
            process.nextTick(function() {
                eval(q);   // sink on 3-level-captured source
            });
        });
    }, 10);
    res.send('ok');
});
