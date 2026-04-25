// HTML escape before XSS sink — correct encoding type.
//
// he.encode is classified as Sanitizer(Cap::HTML_ESCAPE) in label rules.
// res.send is a Sink(Cap::HTML_ESCAPE). The taint engine strips the cap
// before a finding is generated, so this should produce 0 taint findings.
//
// Symex encoding modeling is complementary — this fixture confirms
// no regression from the new Encode node recognition.

var express = require('express');
var he = require('he');
var app = express();

app.get('/profile', function(req, res) {
    var name = req.query.name;
    var safe = he.encode(name);
    res.send('<p>Hello ' + safe + '</p>');
});
