const REGISTERS_COUNT: usize = 8;
const MEMORY_SIZE: usize = 1024 * 1024;

#[allow(dead_code)]
pub struct Emulator {
    registers: [u32; REGISTERS_COUNT],
    eflags: u32,
    eip: u32,
    memory: [u8; MEMORY_SIZE],
}

impl Emulator {
    pub fn new() -> Emulator {
        Emulator {
            registers: [0; REGISTERS_COUNT],
            eflags: 0,
            eip: 0,
            memory: [0; MEMORY_SIZE],
        }
    }
}
