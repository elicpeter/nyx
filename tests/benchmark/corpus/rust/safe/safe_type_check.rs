use std::env;
use std::fs;

fn main() {
    let input = env::var("PAGE_NUM").unwrap();
    let page: u32 = input.parse().expect("not a number");
    let path = format!("/data/page_{}.txt", page);
    let contents = fs::read_to_string(&path).unwrap();
    println!("{}", contents);
}
