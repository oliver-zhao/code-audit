// Unsafe memory APIs.
use std::mem;
use std::ptr;

static mut COUNTER: u32 = 0;

pub unsafe fn as_u32(bytes: [u8; 4]) -> u32 {
    mem::transmute::<[u8; 4], u32>(bytes)
}

pub unsafe fn view(ptr: *const u8, len: usize) -> &'static [u8] {
    std::slice::from_raw_parts(ptr, len)
}

#[allow(deprecated)]
pub unsafe fn scratch() -> [u8; 64] {
    mem::uninitialized()
}

pub unsafe fn pick(values: &[u32], index: usize) -> u32 {
    *values.get_unchecked(index)
}

pub unsafe fn grow(buffer: &mut Vec<u8>, len: usize) {
    buffer.set_len(len);
}

pub unsafe fn copy_into(src: &[u8], dst: *mut u8) {
    ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
}
