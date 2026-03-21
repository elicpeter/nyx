const express = require('express');
const app = express();
app.get('/proxy', (req, res) => {
    const url = req.query.url;
    fetch(url).then(r => r.text()).then(t => res.send(t));
});
