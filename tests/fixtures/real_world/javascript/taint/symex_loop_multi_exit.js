var express = require('express');
var app = express();

app.get('/search', function(req, res) {
    var query = req.query.q;
    var result = query;
    for (var i = 0; i < 100; i++) {
        if (result.length > 50) {
            break;
        }
        result = result + "*";
    }
    eval(result);
});
