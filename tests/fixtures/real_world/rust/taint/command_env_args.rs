use std::env;
use std::process::Command;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 {
        let user_cmd = &args[1];
        Command::new(user_cmd)
            .output()
            .expect("failed to execute");
    }
}
