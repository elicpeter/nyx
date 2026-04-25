var express = require('express');
var app = express();

function sanitize(input) {
    return input.replace(/['"]/g, '');
}

app.get('/safe', function(req, res) {
    var name = req.query.name;
    var clean = sanitize(name);
    var client = require('pg').Client();
    client.query("SELECT * FROM users WHERE name = '" + clean + "'");
});
