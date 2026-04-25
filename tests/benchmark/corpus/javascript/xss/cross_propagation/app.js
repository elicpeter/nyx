const express = require('express');
const { render } = require('./transform');
const app = express();
app.get('/page', (req, res) => {
    const name = req.query.name;
    document.write(render(name));
});
