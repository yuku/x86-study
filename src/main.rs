extern crate px86;

fn main() {
    let mut emu = px86::Emulator::new(0x000000, 0x007c00);

    emu.load("files/helloworld.bin");
    emu.run();
}
