var express = require('express');
var axios = require('axios');
var app = express();

app.get('/proxy', function(req, res) {
    var url = req.query.url;
    axios(url).then(function(response) {
        res.send(response.data);
    });
});
