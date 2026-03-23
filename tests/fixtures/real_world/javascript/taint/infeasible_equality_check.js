var express = require('express');
var app = express();

app.get('/action', function(req, res) {
    var action = req.query.action;
    if (action === "safe") {
        if (action === "dangerous") {
            // Infeasible: action === "safe" AND action === "dangerous"
            eval(action);
        }
    }
    eval(action);
});
