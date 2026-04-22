var express = require('express');
var axios = require('axios');
var app = express();

// axios.post(url, data[, config]) — arg 0 is the URL, arg 1 is the request
// body. Attacker-controlled data in arg 1 flowing to a fixed URL is not SSRF.
app.post('/ingest', function(req, res) {
    var record = req.body.record;
    axios.post('https://internal-ingest.example.com/v1/events', record);
    res.status(204).end();
});
