var express = require('express');
var app = express();

app.get('/api', function(req, res) {
    var mode = req.query.mode;
    var result;
    if (mode === "safe") {
        result = "constant";
    } else {
        result = req.query.payload;
    }
    eval(result);
});
