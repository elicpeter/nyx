const express = require('express');
const app = express();

app.get('/profile', (req, res) => {
    const bio = req.query.bio;
    res.send(`<div dangerouslySetInnerHTML={{__html: ${bio}}} />`);
});
