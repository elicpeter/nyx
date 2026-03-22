const express = require('express');
const app = express();
app.get('/info', (req, res) => {
    const name = req.query.name;
    console.log("User requested: " + name);
    res.send("OK");
});
