var express = require('express');
var app = express();

app.get('/user', function(req, res) {
    var id = req.query.id;
    var sql = "SELECT * FROM users WHERE id = '" + id + "'";
    var db = require('pg').Client();
    db.query(sql);
});
