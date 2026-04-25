import React from 'react';
import express, { Request, Response } from 'express';

const app = express();

app.get('/bio', (req: Request, res: Response) => {
    const bio = req.query.bio as string;
    const html = `<p>${bio}</p>`;
    const page = <div dangerouslySetInnerHTML={{ __html: html }} />;
    res.send(page);
});
