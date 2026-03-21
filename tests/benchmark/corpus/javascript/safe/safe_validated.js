const express = require('express');
const { exec } = require('child_process');
const app = express();
const ALLOWED = ['ls', 'pwd', 'whoami'];
app.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    if (!ALLOWED.includes(cmd)) { return res.status(400).send('denied'); }
    exec(cmd);
});
