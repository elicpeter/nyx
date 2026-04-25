const mysql = require('mysql');

function getUserSafe(req, res) {
    const userId = req.query.id;
    const connection = mysql.createConnection({host: 'localhost'});
    connection.query('SELECT * FROM users WHERE id = ?', [userId], function(err, results) {
        res.json(results);
    });
}
