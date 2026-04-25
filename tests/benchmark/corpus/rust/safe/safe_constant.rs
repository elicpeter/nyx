use std::process::Command;

fn main() {
    Command::new("ls").arg("-la").status().unwrap();
}
