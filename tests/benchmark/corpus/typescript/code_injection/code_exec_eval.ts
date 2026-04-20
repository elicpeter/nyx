import express, { Request, Response } from 'express';
const app = express();

app.get('/calc', (req: Request, res: Response) => {
    const expr: string = req.query.expr as string;
    const result: number = eval(expr);
    res.json({ result });
});
