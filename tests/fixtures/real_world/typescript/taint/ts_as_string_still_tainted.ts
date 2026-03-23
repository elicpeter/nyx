import express from 'express';
const app = express();
app.get('/run', (req, res) => {
    const input = req.query.cmd;
    const cmd = input as string;
    eval(cmd);
});
