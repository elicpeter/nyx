var express = require('express');
var mysql = require('mysql');
var app = express();
var connection = mysql.createConnection({host: 'localhost'});

app.get('/items', function(req, res) {
    var page = parseInt(req.query.page);
    var offset = page * 10;
    connection.query("SELECT * FROM items LIMIT 10 OFFSET " + offset);
});
