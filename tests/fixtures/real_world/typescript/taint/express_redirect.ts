import express from 'express';
var app = express();

app.get('/go', function(req: any, res: any) {
    var url = req.query.url;
    res.redirect(url);
});

app.get('/go-encoded', function(req: any, res: any) {
    var url = req.query.url;
    var encoded = encodeURIComponent(url);
    res.redirect(encoded);
});
