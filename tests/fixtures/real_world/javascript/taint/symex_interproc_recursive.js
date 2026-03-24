var express = require('express');
var app = express();

function traverse(input) {
    if (!input) {
        return "";
    }
    return input + traverse(input.substring(1));
}

app.get('/test', function(req, res) {
    var data = req.query.input;
    var result = traverse(data);
    res.send(result);
});
