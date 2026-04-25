var express = require('express');
var app = express();

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

app.get('/greet', function(req, res) {
    var name = req.query.name;
    var safe = escapeHtml(name);
    var el = document.getElementById('greeting');
    el.innerHTML = '<h1>Hello ' + safe + '</h1>';
});
