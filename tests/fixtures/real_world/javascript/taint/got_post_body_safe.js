var express = require('express');
var got = require('got');
var app = express();

// got({url, json, body, headers, prefixUrl}) — destination-bearing fields are
// `url` / `prefixUrl`. Body-ish fields (`json`, `body`, `headers`) are NOT
// destination. Under the destination-aware gate a tainted `json` field must
// not fire SSRF when `url` is fixed.
app.post('/ingest', function(req, res) {
    var record = req.body.record;
    got({
        method: 'POST',
        url: 'https://internal-ingest.example.com/v1/events',
        json: record,
    });
    res.status(204).end();
});
