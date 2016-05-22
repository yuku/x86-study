extern crate px86;

use std::env;

const MEMORY_SIZE: usize = 1024 * 1024;

fn main() {
    if let Some(path) = env::args().nth(1) {
        px86::emulate(MEMORY_SIZE, &path);
    } else {
        println!("usage: cargo run path/to/binary");
    }
}
