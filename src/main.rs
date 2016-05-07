extern crate px86;

use std::env;

fn main() {
    if let Some(path) = env::args().nth(1) {
        px86::emulate(&path);
    } else {
        println!("usage: cargo run path/to/binary");
    }
}
