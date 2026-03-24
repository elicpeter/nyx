var express = require('express');
var mysql = require('mysql');
var app = express();
var connection = mysql.createConnection({host: 'localhost'});

app.get('/flags', function(req, res) {
    var flags = req.query.flags;
    var result = flags | 0x01;
    connection.query("SELECT * FROM t WHERE flags=" + result);
});
