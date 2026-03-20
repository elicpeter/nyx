use std::process::Command;

fn list_directory() {
    if let Ok(output) = Command::new("ls").arg("-la").arg("/tmp").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("{}", stdout);
    }
}
