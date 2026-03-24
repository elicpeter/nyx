var express = require('express');
var mysql = require('mysql');
var app = express();
var connection = mysql.createConnection({host: 'localhost'});

app.get('/field', function(req, res) {
    var header = req.query.h;
    var shifted = header >> 4;
    var field = shifted & 0x0F;
    connection.query("SELECT * FROM t WHERE field=" + field);
});
