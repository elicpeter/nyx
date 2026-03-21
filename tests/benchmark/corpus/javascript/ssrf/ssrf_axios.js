const express = require('express');
const axios = require('axios');
const app = express();
app.get('/proxy', (req, res) => {
    const url = req.query.url;
    axios(url).then(r => res.send(r.data));
});
