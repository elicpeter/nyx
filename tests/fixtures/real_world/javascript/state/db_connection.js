var mysql = require('mysql');

function queryUnsafe() {
    var conn = mysql.createConnection({ host: 'localhost' });
    conn.connect();
    conn.query('SELECT 1', function(err, results) {
        console.log(results);
    });
    // Missing conn.end()
}

function querySafe() {
    var conn = mysql.createConnection({ host: 'localhost' });
    conn.connect();
    conn.query('SELECT 1', function(err, results) {
        console.log(results);
        conn.end();
    });
}
