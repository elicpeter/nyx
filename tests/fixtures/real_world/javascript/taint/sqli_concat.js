var mysql = require('mysql');

function getUser(connection, userId) {
    var query = 'SELECT * FROM users WHERE id = ' + userId;
    connection.query(query, function(err, results) {
        return results;
    });
}

function getUserSafe(connection, userId) {
    connection.query('SELECT * FROM users WHERE id = ?', [userId], function(err, results) {
        return results;
    });
}
