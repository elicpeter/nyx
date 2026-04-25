var express = require('express');
var app = express();

app.get('/row', function(req, res) {
    var rawPage = req.query.page;
    var page = parseInt(rawPage, 10);
    var el = document.getElementById('row-' + page);
    el.innerHTML = '<tr data-page="' + page + '"><td>Row</td></tr>';
});
