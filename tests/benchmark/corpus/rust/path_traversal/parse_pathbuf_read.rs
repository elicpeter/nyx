use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // A path component parsed into a PathBuf is NOT numeric.  The
    // `let p: PathBuf` annotation must override the conservative
    // bare-`parse` -> Int heuristic so the FILE_IO flow still fires
    // (real-repo shape: sudo-rs / tar-rs username-or-path parse).
    let raw = env::var("USER_PATH").unwrap();
    let p: PathBuf = raw.parse().unwrap();
    let contents = fs::read(p).unwrap();
    println!("{:?}", contents);
}
