use std::env;
use std::process::Command;

fn process_env_commands() {
    if let Ok(cmd) = env::var("CMD") {
        Command::new("sh").arg("-c").arg(&cmd).output().unwrap();
    }

    let mut items: Vec<String> = vec![];
    while let Some(item) = items.pop() {
        println!("{}", item);
    }
}
