// Vulnerable counterpart — bare `connection.query(...)` and chained
// `db.query(...).then(...)` whose arg 0 is concatenated with attacker
// input.  Both must still fire as SQL_QUERY sinks: the chain has no
// ORM-method outer call (`.then` is a Promise method, not an ORM
// accessor), and arg 0 is not a string literal in the second case.

import express, { Request, Response } from 'express';

declare const connection: any;
declare const db: any;

const app = express();

app.get('/user', (req: Request, res: Response) => {
    const name = req.query.name as string;
    // bare SQL — real SQLi sink, no chain
    connection.query(`SELECT * FROM users WHERE name = '${name}'`);
});

app.get('/by-id', async (req: Request, res: Response) => {
    const id = req.query.id as string;
    // chained `.then` is a Promise method, not an ORM accessor; arg 0 is
    // also a binary_expression (not a string literal) so the ORM-shape
    // recogniser refuses to suppress.
    db.query("SELECT * FROM users WHERE id = " + id).then((rows: any) => res.json(rows[0]));
});
