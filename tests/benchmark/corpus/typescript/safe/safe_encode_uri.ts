import express, { Request, Response } from 'express';
import axios from 'axios';

const app = express();

app.get('/lookup', async (req: Request, res: Response) => {
    const term = req.query.term as string;
    const encoded = encodeURIComponent(term);
    const data = await axios.get(`https://api.example.com/search?q=${encoded}`);
    res.json(data.data);
});
