import express, { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';

const app = express();
const prisma = new PrismaClient();

app.get('/search', async (req: Request, res: Response) => {
    const name = req.query.name as string;
    const rows = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name = '${name}'`);
    res.json(rows);
});
