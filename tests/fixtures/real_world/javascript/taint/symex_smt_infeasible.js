var express = require('express');
var app = express();

app.get('/test', function(req, res) {
    var x = parseInt(req.query.x);
    var y = parseInt(req.query.y);
    if (x > y) {
        if (y > x) {
            // Dead code: x > y AND y > x is impossible.
            // PathEnv tracks per-variable intervals and cannot detect this
            // cross-variable contradiction. SMT (Z3) can prove it infeasible.
            eval(req.query.payload);
        }
    }
});
