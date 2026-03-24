const express = require('express');
const { exec } = require('child_process');
const app = express();

function buildCommand(userInput) {
    return 'grep ' + userInput + ' /var/log/app.log';
}

app.get('/logs', (req, res) => {
    const filter = req.query.filter;
    const cmd = buildCommand(filter);
    exec(cmd);
});
