use std::fs::File;
use std::io::Read;

fn process(path: &str) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut buf = String::new();
    f.read_to_string(&mut buf).ok()?;
    if buf.is_empty() {
        return None; // f dropped by RAII, safe
    }
    Some(buf)
}
