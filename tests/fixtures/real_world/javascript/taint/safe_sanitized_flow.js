var express = require('express');
var app = express();

app.get('/greet', function(req, res) {
    var name = req.query.name;
    var clean = DOMPurify.sanitize(name);
    var el = document.getElementById('output');
    if (el) {
        el.innerHTML = clean;
    }
});
