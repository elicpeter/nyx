use std::env;

fn fetch_url() {
    let url = env::var("TARGET_URL").unwrap();
    reqwest::get(&url);
}
