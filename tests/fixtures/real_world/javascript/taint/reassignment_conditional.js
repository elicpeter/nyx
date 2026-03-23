var express = require('express');
var app = express();
app.get('/greet', function(req, res) {
    var name = req.query.name;
    if (name.length > 10) {
        name = "fallback";
    }
    eval(name);
});
