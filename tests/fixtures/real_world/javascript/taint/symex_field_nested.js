var express = require('express');
var app = express();
app.post('/login', function(req, res) {
    var username = req.body.username;
    var query = "SELECT * FROM users WHERE name = '" + username + "'";
    var db = require('pg').Client();
    db.query(query);
});
