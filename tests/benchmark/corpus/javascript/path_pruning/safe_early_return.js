const express = require('express');
const { exec } = require('child_process');
const app = express();

const ALLOWED = ['status', 'version', 'uptime'];

app.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    if (!ALLOWED.includes(cmd)) {
        return res.status(403).send('forbidden');
    }
    exec(cmd);
});
