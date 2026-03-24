use std::env;

fn main() {
    let url = env::var("TARGET_URL").unwrap();
    reqwest::get(&url);
}
