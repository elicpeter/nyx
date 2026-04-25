var express = require('express');
var app = express();

app.get('/safe', function(req, res) {
    var items = [];
    items.push("safe_constant");
    items.push("another_constant");
    res.send('<ul>' + items.join('') + '</ul>');
});
