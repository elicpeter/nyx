var express = require('express');
var app = express();

app.get('/search', function(req, res) {
    var input = req.query.q;
    var cleaned = input.trim().toLowerCase();
    var query = "SELECT * FROM items WHERE name = '" + cleaned + "'";
    var client = require('pg').Client();
    client.query(query);
});
