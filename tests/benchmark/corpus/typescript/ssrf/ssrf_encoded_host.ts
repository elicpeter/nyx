import express, { Request, Response } from 'express';
import axios from 'axios';

const app = express();

app.get('/fetch', async (req: Request, res: Response) => {
    const host = req.query.host as string;
    const encodedHost = encodeURIComponent(host);
    const data = await axios.get(`https://${encodedHost}/api`);
    res.json(data.data);
});
