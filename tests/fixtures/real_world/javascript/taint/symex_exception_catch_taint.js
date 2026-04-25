var express = require('express');
var app = express();

app.get('/api', function(req, res) {
    var userInput = req.query.data;
    try {
        JSON.parse(userInput);
    } catch (e) {
        res.send("Error: " + userInput);
    }
});
