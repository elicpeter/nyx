use std::fs::File;

fn drop_file() {
    let f = File::open("/tmp/test").unwrap();
    drop(f);
}
