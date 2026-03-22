const express = require('express');
const app = express();

app.get('/item', (req, res) => {
    const id = parseInt(req.query.id, 10);
    res.send(`<p>Item ${id}</p>`);
});
