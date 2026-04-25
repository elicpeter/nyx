var express = require('express');
var app = express();

app.get('/banner', function(req, res) {
    var pathname = req.query.pathname;
    var isLoginPage = pathname === '/login'
                   || pathname === '/login.html';
    var banner = isLoginPage
        ? '<div class="banner-compact">Please log in</div>'
        : '<div class="banner-full">Welcome back</div>';
    res.send(banner);
});
