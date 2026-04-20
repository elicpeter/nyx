use std::env;
use rusqlite::Connection;

fn main() {
    let user_id = env::var("USER_ID").unwrap();
    let conn = Connection::open("app.db").unwrap();
    let sql = format!("SELECT name FROM users WHERE id = {}", user_id);
    conn.execute(&sql, []).unwrap();
}
