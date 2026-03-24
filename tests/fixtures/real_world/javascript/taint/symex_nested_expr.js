var express = require('express');
var app = express();

app.get('/api', function(req, res) {
    var x = req.query.offset;
    var y = x * 2;
    var z = y + 1;
    var query = "SELECT * FROM t LIMIT " + z;
    var client = require('pg').Client();
    client.query(query);
});
