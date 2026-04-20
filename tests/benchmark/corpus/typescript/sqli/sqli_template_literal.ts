import express, { Request, Response } from 'express';
import { Pool } from 'pg';

const app = express();
const pool = new Pool();

app.get('/user', (req: Request, res: Response) => {
    const id = req.query.id as string;
    pool.query(`SELECT * FROM users WHERE id = '${id}'`);
});
