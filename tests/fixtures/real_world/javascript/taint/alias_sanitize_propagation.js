var express = require('express');
var app = express();

app.get('/alias', function(req, res) {
    var obj = {};
    obj.data = req.query.input;
    var alias = obj;
    alias.data = DOMPurify.sanitize(alias.data);
    res.send(obj.data);
});
