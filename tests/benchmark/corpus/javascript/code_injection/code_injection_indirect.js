const express = require('express');
const app = express();
app.post('/render', (req, res) => {
    const input = req.body.template;
    const compiled = "return " + input;
    const fn = new Function(compiled);
    res.send(fn());
});
