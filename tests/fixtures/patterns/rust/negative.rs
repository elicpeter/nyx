// Negative fixture: none of the security-relevant patterns should fire here.

fn safe_option_handling() {
    let x: Option<i32> = Some(1);
    // Using match instead of unwrap
    match x {
        Some(v) => println!("{}", v),
        None => println!("none"),
    }
}

fn safe_result_handling() -> Result<(), String> {
    let x: Result<i32, String> = Ok(1);
    // Using ? instead of unwrap
    let _v = x?;
    Ok(())
}

fn safe_copy() {
    let src = vec![1, 2, 3];
    let mut dst = vec![0; 3];
    // Safe copy via clone
    dst.clone_from(&src);
}

fn safe_cast() {
    let x: u32 = 42;
    // Widening cast is fine
    let _ = x as u64;
}

fn safe_string_ops() {
    let s = String::from("hello");
    let _ = s.len();
    let _ = s.is_empty();
}
