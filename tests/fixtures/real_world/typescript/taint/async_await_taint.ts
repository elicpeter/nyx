import express from 'express';
var app = express();

app.get('/proxy', async function(req: any, res: any) {
    var url = req.query.url;
    var response = await fetch(url);
    var body = await response.text();
    res.send(body);
});
