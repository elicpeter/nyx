var express = require('express');
var app = express();

app.get('/summary', function(req, res) {
    var items = req.query.items;
    var count = items.length;
    var el = document.getElementById('summary');
    el.innerHTML = '<p>You have <strong>' + count + '</strong> items</p>';
});
