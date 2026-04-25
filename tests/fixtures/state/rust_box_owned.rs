fn boxed() {
    let b = Box::new(42);
    println!("{}", b);
    // b dropped — no leak
}
