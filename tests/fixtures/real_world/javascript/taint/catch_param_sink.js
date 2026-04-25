var express = require('express');
var app = express();

app.get('/catch-param-xss', function(req, res) {
    try {
        JSON.parse(req.query.data);
    } catch (e) {
        res.send('<h1>Error: ' + e + '</h1>');
    }
});
