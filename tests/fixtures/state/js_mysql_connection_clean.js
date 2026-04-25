var mysql = require('mysql');

function querySafe() {
    var conn = mysql.createConnection({ host: 'localhost' });
    conn.query('SELECT 1');
    conn.end();
}
