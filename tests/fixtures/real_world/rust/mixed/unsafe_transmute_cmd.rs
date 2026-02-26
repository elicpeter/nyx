use std::env;
use std::mem;
use std::process::Command;

fn main() {
    let input = env::var("INPUT").unwrap();
    let bytes = input.as_bytes();
    let val: u32 = unsafe { mem::transmute([bytes[0], bytes[1], bytes[2], bytes[3]]) };

    let cmd = format!("echo {}", val);
    Command::new("sh").arg("-c").arg(&cmd).output().unwrap();
}
