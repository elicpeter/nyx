var mysql = require('mysql');

function queryUnsafe() {
    var conn = mysql.createConnection({ host: 'localhost' });
    conn.query('SELECT 1');
    // Missing conn.end()
}
