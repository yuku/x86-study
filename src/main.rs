extern crate px86;

fn main() {
    let mut emu = px86::Emulator::new(0x7c00, 0x7c00);

    emu.load("files/helloworld.bin");
    emu.run();
}
