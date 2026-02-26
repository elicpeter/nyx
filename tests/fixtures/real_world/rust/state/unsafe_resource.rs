use std::alloc::{alloc, dealloc, Layout};

unsafe fn alloc_leak() {
    let layout = Layout::new::<[u8; 1024]>();
    let ptr = alloc(layout);
    // never deallocated
}

unsafe fn alloc_clean() {
    let layout = Layout::new::<[u8; 1024]>();
    let ptr = alloc(layout);
    dealloc(ptr, layout);
}
