use std::alloc::{alloc, Layout};

unsafe fn leak() {
    let layout = Layout::new::<[u8; 1024]>();
    let _ptr = alloc(layout);
    // never deallocated
}
