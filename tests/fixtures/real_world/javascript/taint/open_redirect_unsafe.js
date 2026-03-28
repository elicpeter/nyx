var express = require('express');
var app = express();

app.get('/go', function(req, res) {
    var next = req.query.next;
    res.redirect(next);
});
