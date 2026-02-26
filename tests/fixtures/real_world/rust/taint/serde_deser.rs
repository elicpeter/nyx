use std::env;

fn parse_user_json() {
    let input = env::var("JSON_INPUT").unwrap();
    let _value: serde_json::Value = serde_json::from_str(&input).unwrap();
}
