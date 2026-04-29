use std::fs::File;
use std::io::Read;

fn read_file() {
    let mut f = File::open("/tmp/test").unwrap();
    let mut buf = String::new();
    f.read_to_string(&mut buf).unwrap();
    // f dropped by RAII, no leak
}
