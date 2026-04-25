var express = require('express');
var app = express();

function wrapQuery(input) {
    return "SELECT * FROM users WHERE id = " + input;
}

app.get('/user', function(req, res) {
    var id = req.query.id;
    var query = wrapQuery(id);
    var client = require('pg').Client();
    client.query(query);
});
