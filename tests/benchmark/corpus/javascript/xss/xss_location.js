const express = require('express');
const app = express();
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    location.href = url;
});
