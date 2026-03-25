// URL encoding at SQL sink — wrong encoding type.
//
// encodeURIComponent strips Cap::URL_ENCODE in the taint engine, but
// client.query is a Sink(Cap::SQL_QUERY). URL encoding does NOT protect
// against SQL injection.
//
// Phase 28: symex should model the encoding structurally and produce a
// heuristic mismatch note in the witness.

var express = require('express');
var app = express();

app.get('/search', function(req, res) {
    var userInput = req.query.q;
    var encoded = encodeURIComponent(userInput);
    var query = "SELECT * FROM items WHERE name = '" + encoded + "'";
    var pg = require('pg');
    var client = new pg.Client();
    client.query(query);
});
