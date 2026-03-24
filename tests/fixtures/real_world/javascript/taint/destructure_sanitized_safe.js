var express = require('express');
var DOMPurify = require('dompurify');
var app = express();

app.get('/destruct-safe', function(req, res) {
    var input = DOMPurify.sanitize(req.query.name);
    var { length } = input;
    res.send(length);
});
