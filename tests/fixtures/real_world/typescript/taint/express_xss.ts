import express from 'express';
var app = express();

app.get('/greet', function(req: any, res: any) {
    var name = req.query.name;
    res.send('<h1>Hello ' + name + '</h1>');
});

app.get('/greet-safe', function(req: any, res: any) {
    var name = req.query.name;
    var clean = DOMPurify.sanitize(name);
    res.send('<h1>Hello ' + clean + '</h1>');
});
