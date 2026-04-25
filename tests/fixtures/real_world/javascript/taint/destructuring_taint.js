var express = require('express');
var app = express();

// Two separate field reads — tests that each source.field independently taints
app.get('/multi-field', function(req, res) {
    var name = req.query.name;
    var age = req.query.age;
    res.send(age);
});
