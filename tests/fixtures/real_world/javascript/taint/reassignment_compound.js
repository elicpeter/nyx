var express = require('express');
var app = express();
app.get('/greet', function(req, res) {
    var name = req.query.name;
    name = name + " suffix";
    eval(name);
});
