const express = require('express');
const app = express();
app.get('/users', (req, res) => {
    const id = req.query.id;
    eval("SELECT * FROM users WHERE id = " + id);
});
