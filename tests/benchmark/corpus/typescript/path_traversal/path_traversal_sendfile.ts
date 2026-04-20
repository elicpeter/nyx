import express, { Request, Response } from 'express';
const app = express();

app.get('/file', (req: Request, res: Response) => {
    const fileName = req.query.path as string;
    res.sendFile(fileName);
});
