use std::mem;

unsafe fn reinterpret(data: &[u8]) -> &[u32] {
    let ptr = data.as_ptr() as *const u32;
    let len = data.len() / 4;
    std::slice::from_raw_parts(ptr, len)
}

fn transmute_example() {
    let val: u32 = 0x41414141;
    let bytes: [u8; 4] = unsafe { mem::transmute(val) };
}
