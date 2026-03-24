use std::env;

fn fetch_data(url: &str) {
    reqwest::get(url);
}

fn main() {
    let target = env::var("API_URL").unwrap();
    fetch_data(&target);
}
