var express = require('express');
var app = express();

app.get('/items', function(req, res) {
    var page = parseInt(req.query.page);
    var offset = page * 10;
    db.query("SELECT * FROM items LIMIT 10 OFFSET " + offset);
});
