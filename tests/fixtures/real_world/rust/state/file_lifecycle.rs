use std::fs::File;
use std::io::Read;

fn read_and_drop() -> String {
    let mut f = File::open("/tmp/test").unwrap();
    let mut buf = String::new();
    f.read_to_string(&mut buf).unwrap();
    buf
    // f dropped automatically by RAII
}

fn explicit_drop() {
    let f = File::open("/tmp/test").unwrap();
    drop(f);
}
