import express, { Request, Response } from 'express';
import axios from 'axios';

const app = express();

app.get('/proxy', async (req: Request, res: Response) => {
    const target = req.query.url as string;
    const response = await axios.get(target);
    res.send(response.data);
});
