use std::fs;
use std::io;

fn read_config(path: &str) -> Result<String, io::Error> {
    let content = fs::read_to_string(path)?;
    Ok(content)
}

fn read_config_panicky(path: &str) -> String {
    fs::read_to_string(path).unwrap()
}

fn read_config_expect(path: &str) -> String {
    fs::read_to_string(path).expect("config must exist")
}
