var express = require('express');
var app = express();

app.get('/api', function(req, res) {
    try {
        var payload = req.query.payload;
        JSON.parse(payload);
    } catch (e) {
        var msg = "Parse error: " + payload;
        res.send(msg);
    }
});
