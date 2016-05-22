mod emulator;
mod instructions;
mod modrm;

pub fn emulate(memory_size: usize, path: &str) {
    let mut emu = emulator::Emulator::new(memory_size, 0x7c00, 0x7c00);
    emu.load(path);
    emu.run();
    emu.dump_registers();
}
