const express = require('express');
const app = express();
app.get('/calc', (req, res) => {
    const input = req.query.value;
    if (typeof input !== 'number') {
        return res.status(400).send('bad');
    }
    eval("compute(" + input + ")");
});
