var express = require('express');
var app = express();

// Prism-shaped FP: tainted condition selects between two static-literal HTML
// fragments. Neither branch carries attacker-controlled data, so the innerHTML
// sink must not fire on the condition's content.
app.get('/banner', function(req, res) {
    var useCompactBanner = req.query.compact;
    var banner = useCompactBanner
        ? '<div class="banner-compact">Welcome</div>'
        : '<div class="banner-full">Welcome back</div>';
    res.send(banner);
});
