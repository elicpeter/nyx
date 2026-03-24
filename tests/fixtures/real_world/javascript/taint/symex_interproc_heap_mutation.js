var express = require('express');
var app = express();

function setName(obj, input) {
    obj.name = input;
}

app.get('/profile', function(req, res) {
    var user = {};
    setName(user, req.query.name);
    var pg = require('pg').Client();
    pg.query("SELECT * FROM users WHERE name = " + user.name);
});
