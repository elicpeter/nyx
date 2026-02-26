use std::mem;
use std::fs::File;

fn forget_file() {
    let f = File::open("/tmp/test").unwrap();
    mem::forget(f); // resource leak!
}
