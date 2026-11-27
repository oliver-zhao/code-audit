// Safe equivalents of the unsafe memory APIs.
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU32, Ordering};

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn as_u32(bytes: [u8; 4]) -> u32 {
    COUNTER.fetch_add(1, Ordering::Relaxed);
    u32::from_ne_bytes(bytes)
}

pub fn scratch() -> [u8; 64] {
    let buffer = MaybeUninit::<[u8; 64]>::zeroed();
    unsafe { buffer.assume_init() }
}

pub fn pick(values: &[u32], index: usize) -> Option<u32> {
    values.get(index).copied()
}

pub fn grow(buffer: &mut Vec<u8>, len: usize) {
    buffer.resize(len, 0);
}

pub fn copy_into(src: &[u8], dst: &mut [u8]) {
    dst[..src.len()].copy_from_slice(src);
}
