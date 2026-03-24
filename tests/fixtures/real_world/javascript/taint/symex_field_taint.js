var express = require('express');
var app = express();
app.get('/api', function(req, res) {
    var input = req.query.name;
    var user = {};
    user.name = input;
    var query = "SELECT * FROM users WHERE name = '" + user.name + "'";
    var db = require('pg').Client();
    db.query(query);
});
