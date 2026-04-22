// Cross-file sanitizer applied before a sink: no XSS finding expected.
// The cross-file summary path already recognises encodeURIComponent
// as a sanitizer; the regression guard here is that CF-2 inline
// re-analysis does not *introduce* a finding by mis-resolving taint.

const { xssSafe } = require('./security');
const express = require('express');
const app = express();

app.get('/profile', function (req, res) {
    const name = req.query.name;
    const clean = xssSafe(name);
    res.send('<h1>Hello ' + clean + '</h1>');
});
