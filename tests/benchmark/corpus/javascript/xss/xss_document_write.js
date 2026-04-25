const express = require('express');
const app = express();
app.get('/page', (req, res) => {
    const input = req.query.content;
    document.write(input);
});
