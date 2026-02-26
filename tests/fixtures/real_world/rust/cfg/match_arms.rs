use std::env;
use std::process::Command;

enum Action {
    Run(String),
    Log(String),
    Quit,
}

fn handle(action: Action) {
    match action {
        Action::Run(cmd) => {
            Command::new("sh").arg("-c").arg(&cmd).output().unwrap();
        }
        Action::Log(msg) => println!("{}", msg),
        Action::Quit => std::process::exit(0),
    }
}
