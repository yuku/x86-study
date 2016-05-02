extern crate px86;

fn main() {
    let mut emu = px86::Emulator::new();

    emu.load("files/helloworld.bin");
    emu.run();
}
