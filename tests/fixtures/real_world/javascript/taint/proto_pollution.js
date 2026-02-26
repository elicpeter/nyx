function merge(target, source) {
    for (var key in source) {
        if (typeof source[key] === 'object') {
            target[key] = merge(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

var express = require('express');
var app = express();

app.post('/config', function(req, res) {
    var defaults = { theme: 'light', lang: 'en' };
    var config = merge(defaults, req.body);
    res.json(config);
});
