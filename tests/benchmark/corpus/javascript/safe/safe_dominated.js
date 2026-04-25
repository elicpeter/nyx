const express = require('express');
const { exec } = require('child_process');
const app = express();
const ALLOWED = ['ls', 'pwd'];
app.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    if (!ALLOWED.includes(cmd)) { return res.status(403).send('denied'); }
    exec(cmd);
});
