var express = require('express');
var app = express();

// Ternary where both branches apply a sanitizer to the tainted value. After
// decomposition, each branch holds a Sanitizer-labelled Call node that strips
// HTML_ESCAPE caps. The phi at the join joins two sanitized values, so the
// sink at res.send receives clean data.
app.get('/echo', function(req, res) {
    var name = req.query.name;
    var pick = req.query.mode;
    var safe = pick
        ? escapeHtml(name)
        : escapeHtml(name.toUpperCase());
    res.send(safe);
});
