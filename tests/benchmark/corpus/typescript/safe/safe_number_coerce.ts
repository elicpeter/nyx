import express, { Request, Response } from 'express';
import { Pool } from 'pg';

const app = express();
const pool = new Pool();

app.get('/user', (req: Request, res: Response) => {
    const id = Number(req.query.id);
    if (!Number.isFinite(id)) {
        res.status(400).send('bad id');
        return;
    }
    pool.query(`SELECT * FROM users WHERE id = ${id}`);
});
