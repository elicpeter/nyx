const express = require('express');
const app = express();
app.get('/greet', (req, res) => {
    let name = req.query.name;
    name = "Guest";
    document.getElementById('output').innerHTML = name;
});
