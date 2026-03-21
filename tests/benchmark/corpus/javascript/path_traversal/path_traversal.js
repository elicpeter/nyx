const express = require('express');
const path = require('path');
const app = express();
app.get('/file', (req, res) => {
    const filePath = req.query.path;
    res.sendFile(filePath);
});
