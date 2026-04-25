var express = require('express');
var mysql = require('mysql');
var app = express();
var connection = mysql.createConnection({host: 'localhost'});

app.get('/items', function(req, res) {
    var name = req.query.name;
    connection.query("SELECT * FROM items WHERE name = '" + name + "'");
});
