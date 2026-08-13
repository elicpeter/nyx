// Recall guard for the ORM-UID-reference suppression: relaxing the
// `db.query(UID).<orm_method>(...)` recogniser to accept variable / const /
// member UID references must NOT blanket-suppress every `query(variable)`.
// Here the variable holds *raw interpolated SQL* and there is NO trailing ORM
// method, so the ORM-shape recogniser does not fire and the SQL sink must
// still be reported.

import express, { Request, Response } from 'express';

declare const connection: any;
declare const strapi: any;

const app = express();

app.get('/user', (req: Request, res: Response) => {
    const name = req.query.name as string;
    // variable holds raw SQL built from attacker input; no ORM-method chain.
    const sql = `SELECT * FROM users WHERE name = '${name}'`;
    connection.query(sql);
});

app.get('/lookup', (req: Request, res: Response) => {
    const term = req.query.term as string;
    // concatenation arg 0 even *with* an ORM-method chain is refused
    // (binary_expression is not a model-UID reference).
    return strapi.db.query('api::article.article' + term).findMany({ where: {} });
});
