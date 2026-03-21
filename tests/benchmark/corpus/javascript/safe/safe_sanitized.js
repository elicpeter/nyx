const express = require('express');
const DOMPurify = require('dompurify');
const app = express();
app.get('/greet', (req, res) => {
    const name = req.query.name;
    const clean = DOMPurify.sanitize(name);
    document.getElementById('output').innerHTML = clean;
});
