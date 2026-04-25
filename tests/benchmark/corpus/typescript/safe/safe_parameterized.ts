import express, { Request, Response } from 'express';
import { Pool } from 'pg';

const app = express();
const pool = new Pool();

app.get('/user', async (req: Request, res: Response) => {
    const id = req.query.id as string;
    const r = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    res.json(r.rows);
});
