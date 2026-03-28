const mysql = require('mysql');

function handleRequest(req, res) {
    const userId = req.query.id;
    const connection = mysql.createConnection({host: 'localhost'});

    // UNSAFE: string concatenation into SQL query
    connection.query("SELECT * FROM users WHERE id = " + userId, function(err, unsafeResult) {
        // SAFE: parameterized query with ? placeholder
        connection.query("SELECT * FROM profiles WHERE user_id = ?", [userId], function(err, safeResult) {
            res.json({ unsafe: unsafeResult, safe: safeResult });
        });
    });
}
