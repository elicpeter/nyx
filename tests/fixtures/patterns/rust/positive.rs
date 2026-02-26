// Positive fixture: each snippet should trigger the named pattern.

use std::mem;
use std::ptr;

// rs.memory.transmute
fn trigger_transmute() {
    let x: u32 = unsafe { mem::transmute(1.0f32) };
    let _ = x;
}

// rs.memory.copy_nonoverlapping
fn trigger_copy_nonoverlapping() {
    let src = [1u8; 4];
    let mut dst = [0u8; 4];
    unsafe { ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), 4) };
}

// rs.memory.get_unchecked
fn trigger_get_unchecked() {
    let v = vec![1, 2, 3];
    let _ = unsafe { v.get_unchecked(0) };
}

// rs.memory.mem_zeroed
fn trigger_mem_zeroed() {
    let _: u64 = unsafe { mem::zeroed() };
}

// rs.memory.ptr_read
fn trigger_ptr_read() {
    let x = 42u32;
    let _ = unsafe { ptr::read(&x) };
}

// rs.quality.unsafe_block
fn trigger_unsafe_block() {
    unsafe {
        let _ = 1;
    }
}

// rs.quality.unsafe_fn
unsafe fn trigger_unsafe_fn() {}

// rs.quality.unwrap
fn trigger_unwrap() {
    let x: Option<i32> = Some(1);
    let _ = x.unwrap();
}

// rs.quality.expect
fn trigger_expect() {
    let x: Option<i32> = Some(1);
    let _ = x.expect("should exist");
}

// rs.quality.panic_macro
fn trigger_panic() {
    panic!("boom");
}

// rs.quality.todo
fn trigger_todo() {
    todo!();
}

// rs.memory.narrow_cast
fn trigger_narrow_cast() {
    let big: u32 = 1000;
    let _ = big as u8;
}

// rs.memory.mem_forget
fn trigger_mem_forget() {
    let v = vec![1, 2, 3];
    mem::forget(v);
}
