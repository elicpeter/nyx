import React from 'react';
import express, { Request, Response } from 'express';

const app = express();

app.get('/bio', (req: Request, res: Response) => {
    const bio = req.query.bio as string;
    const page = <div>{bio}</div>;
    res.send(page);
});
