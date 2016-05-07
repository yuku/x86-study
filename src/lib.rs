mod emulator;
mod instructions;
mod modrm;

pub fn emulate(path: &str) {
    let mut emu = emulator::Emulator::new(0x7c00, 0x7c00);
    emu.load(path);
    emu.run();
    emu.dump_registers();
}
