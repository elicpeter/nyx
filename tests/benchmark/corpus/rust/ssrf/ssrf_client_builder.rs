use std::env;

fn main() {
    let url = env::var("TARGET_URL").unwrap();
    let client = reqwest::Client::new();
    let _ = client.get(&url).send();
}
