var express = require('express');
var app = express();

app.get('/process', function(req, res) {
    var input = req.query.data;
    var processed = input;
    for (var i = 0; i < 10; i++) {
        processed = processed.trim();
    }
    var query = "SELECT * FROM t WHERE x = '" + processed + "'";
    var client = require('pg').Client();
    client.query(query);
});
