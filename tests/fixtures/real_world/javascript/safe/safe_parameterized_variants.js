const mysql = require('mysql');
const { Client, Pool } = require('pg');

// MySQL ? placeholder with connection.query
function mysqlSafe(req, res) {
    const id = req.query.id;
    const connection = mysql.createConnection({host: 'localhost'});
    connection.query('SELECT * FROM users WHERE id = ?', [id], function(err, rows) {
        res.json(rows);
    });
}

// PostgreSQL $1/$2 placeholders with client.query
async function pgClientSafe(req, res) {
    const name = req.query.name;
    const age = req.query.age;
    const client = new Client();
    const result = await client.query('SELECT * FROM users WHERE name = $1 AND age = $2', [name, age]);
    res.json(result.rows);
}

// Pool.query with $1 placeholder
async function pgPoolSafe(req, res) {
    const id = req.params.id;
    const pool = new Pool();
    const result = await pool.query('SELECT email FROM users WHERE id = $1', [id]);
    res.json(result.rows);
}

// db.execute with ? placeholder
function dbExecuteSafe(req, res) {
    const username = req.body.username;
    db.execute('INSERT INTO logs (username) VALUES (?)', [username]);
    res.sendStatus(200);
}

// Template literal (no interpolation) with ? placeholder
function templateLiteralSafe(req, res) {
    const id = req.query.id;
    connection.query(`SELECT * FROM products WHERE id = ?`, [id], function(err, rows) {
        res.json(rows);
    });
}
