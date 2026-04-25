const { Client } = require('pg');

// UNSAFE: template literal with interpolation — not a constant string
async function templateInterpolation(req, res) {
    const table = req.query.table;
    const client = new Client();
    const result = await client.query(`SELECT * FROM ${table} WHERE id = $1`, [req.query.id]);
    res.json(result.rows);
}

// UNSAFE: dynamic variable as first arg — not a string literal
async function dynamicQuery(req, res) {
    const userInput = req.query.q;
    const query = "SELECT * FROM users WHERE name = " + userInput;
    const client = new Client();
    const result = await client.query(query);
    res.json(result.rows);
}

// UNSAFE: concatenation into query string (classic SQLi)
async function concatQuery(req, res) {
    const id = req.query.id;
    const client = new Client();
    const result = await client.query("SELECT * FROM users WHERE id = " + id);
    res.json(result.rows);
}

// UNSAFE: single arg, no params array — ? in string doesn't help without bind params
async function noParamsArray(req, res) {
    const id = req.query.id;
    const client = new Client();
    const result = await client.query("SELECT * FROM users WHERE id = " + id + " OR 1=1");
    res.json(result.rows);
}

// UNSAFE: sequelize.query with raw SQL — ORM raw entry point, not suppressed
async function sequelizeRaw(req, res) {
    const name = req.query.name;
    const results = await sequelize.query("SELECT * FROM users WHERE name = '" + name + "'");
    res.json(results);
}
