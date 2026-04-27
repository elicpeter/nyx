const express = require('express');
const http = require('http');
const app = express();
app.get('/probe', (req, res) => {
    const target = req.query.url;
    http.get(target, response => {
        res.send('ok');
    }).on('error', e => {
        res.status(500).send(e.message);
    });
});
