var express = require('express');
var mysql = require('mysql');
var app = express();
var connection = mysql.createConnection({host: 'localhost'});

app.get('/items', function(req, res) {
    var flags = req.query.flags;
    var safe = flags & 0x07;
    connection.query("SELECT * FROM items WHERE level=" + safe);
});
