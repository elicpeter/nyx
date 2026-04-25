const { Sequelize } = require('sequelize');

async function searchUsers(req, res) {
    const name = req.query.name;
    const sequelize = new Sequelize('sqlite::memory:');
    const results = await sequelize.query("SELECT * FROM users WHERE name = '" + name + "'");
    res.json(results);
}
