var express = require('express');
var app = express();

app.get('/collect', function(req, res) {
    var items = [];
    items.push(req.query.item);
    res.send('<ul>' + items.join('') + '</ul>');
});
