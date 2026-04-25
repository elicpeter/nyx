use std::env;
use rusqlite::Connection;

fn main() {
    let user_id = env::var("USER_ID").unwrap();
    // Rejecting shell metacharacters does NOT make SQL injection safe —
    // the metachar gate only covers shell-family sinks.
    if user_id.contains(";") || user_id.contains("|") {
        return;
    }
    let conn = Connection::open("app.db").unwrap();
    let sql = format!("SELECT name FROM users WHERE id = {}", user_id);
    conn.execute(&sql, []).unwrap();
}
