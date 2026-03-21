const express = require('express');
const app = express();
app.get('/greet', (req, res) => {
    const name = req.query.name;
    document.getElementById('output').innerHTML = name;
});
