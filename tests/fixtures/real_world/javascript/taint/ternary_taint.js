var express = require('express');
var app = express();

app.get('/display', function(req, res) {
    var input = req.query.name;
    var output = input ? input : 'default';
    res.send('<p>' + output + '</p>');
});
