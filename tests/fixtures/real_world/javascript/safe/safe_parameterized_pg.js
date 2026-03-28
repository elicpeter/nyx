const { Client } = require('pg');

async function getUser(req, res) {
    const userId = req.query.id;
    const client = new Client();
    await client.connect();
    const result = await client.query("SELECT * FROM users WHERE id = $1", [userId]);
    res.json(result.rows);
}
