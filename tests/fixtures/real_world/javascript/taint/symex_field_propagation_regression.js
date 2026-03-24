var express = require('express');
var app = express();
app.get('/api', function(req, res) {
    var input = req.query.name;
    var user = {};
    user.id = parseInt(input, 10);
    var query = "SELECT * FROM users WHERE id = " + user.id;
    var db = require('pg').Client();
    db.query(query);
});
