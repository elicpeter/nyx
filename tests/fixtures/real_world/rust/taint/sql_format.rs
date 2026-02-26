use std::env;

fn query_user(user_id: &str) -> String {
    format!("SELECT * FROM users WHERE id = {}", user_id)
}

fn main() {
    let id = env::var("USER_ID").unwrap();
    let query = query_user(&id);
    println!("{}", query);
}
