use std::alloc::{alloc, dealloc, Layout};

unsafe fn clean() {
    let layout = Layout::new::<[u8; 1024]>();
    let ptr = alloc(layout);
    dealloc(ptr, layout);
}
