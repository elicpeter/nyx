const mysql = require('mysql');

function getUser(req, res) {
    const userId = req.query.id;
    const connection = mysql.createConnection({host: 'localhost'});
    const sql = "SELECT * FROM users WHERE id = " + userId;
    connection.query(sql, function(err, results) {
        res.json(results);
    });
}
