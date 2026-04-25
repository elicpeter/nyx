import express from 'express';
const app = express();

app.get('/proxy', function(req: express.Request, res: express.Response) {
    const url = req.query.url as string;
    fetch(url).then(function(response) {
        return response.text();
    }).then(function(body) {
        res.send(body);
    });
});
