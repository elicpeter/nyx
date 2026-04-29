const express = require('express');
const http = require('http');
const app = express();
app.get('/health', (req, res) => {
    http.get('http://internal-health.localhost/ping', response => {
        res.send('ok');
    }).on('error', e => {
        res.status(500).send(e.message);
    });
});
