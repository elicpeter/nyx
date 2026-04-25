const express = require('express');
const app = express();
app.get('/calc', (req, res) => {
    const expr = req.query.expr;
    const result = eval(expr);
    res.send(String(result));
});
