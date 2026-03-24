const express = require('express');
const app = express();

function cleanInput(s) {
    return encodeURIComponent(s);
}

app.get('/search', (req, res) => {
    const query = req.query.q;
    const safe = cleanInput(query);
    res.send('<p>Results for: ' + safe + '</p>');
});
