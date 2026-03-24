var express = require('express');
var app = express();

app.get('/data', function(req, res) {
    var input = req.query.id;
    var table;
    if (input.length > 10) {
        table = "users";
    } else {
        table = input;
    }
    var client = require('pg').Client();
    client.query("SELECT * FROM " + table);
});
