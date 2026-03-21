const express = require('express');
const { exec } = require('child_process');
const app = express();
app.get('/run', (req, res) => {
    const cmd = req.query.cmd;
    exec(cmd);
});
