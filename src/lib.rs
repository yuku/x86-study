use std::io::Read;
use std::fs::File;
use std::num::Wrapping;

const REGISTERS_COUNT: usize = 8;
const REGISTER_NAMES: [&'static str; REGISTERS_COUNT] = [
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"
];
const ESP: usize = 4;
const MEMORY_SIZE: usize = 1024 * 1024;

#[allow(dead_code)]
pub struct Emulator {
    registers: [u32; REGISTERS_COUNT],
    eflags: u32,
    eip: u32,
    memory: [u8; MEMORY_SIZE],
}

impl Emulator {
    pub fn new(eip: u32, esp: u32) -> Emulator {
        let mut emu = Emulator {
            registers: [0; REGISTERS_COUNT],
            eflags: 0,
            eip: 0,
            memory: [0; MEMORY_SIZE],
        };
        emu.registers[ESP] = esp;
        emu.eip = eip;
        emu
    }

    pub fn load(&mut self, path: &str) {
        let mut f = File::open(path)
            .expect(&format!("failed to read {}", path));
        f.read(&mut self.memory)
            .expect(&format!("filed to load {} to memory", path));
    }

    pub fn run(&mut self) {
        let memory_size = self.memory.len() as u32;

        while self.eip < memory_size {
            self.execute();

            if self.eip == 0 {
                println!("end of program.");
                self.dump_registers();
                break;
            }
        }
    }

    fn execute(&mut self) {
        let code = self.get_code8(0);

        println!("EIP = {eip:#08X}, Code = {code:#08X}", eip = self.eip, code = code);

        match code {
            0xB8...0xBF => self.mov_r32_imm32(),
            0xEB => self.short_jump(),
            _ => {
                self.dump_registers();
                panic!("not implemented");
            },
        }
    }

    fn get_code8(&self, index: u32) -> u8 {
        self.memory[(self.eip + index) as usize]
    }

    fn get_code32(&self, index: u32) -> u32 {
        let mut code = 0u32;
        for i in 0..4 {
            code |= (self.get_code8(index + i) as u32) << (i * 8);
        }
        code
    }

    fn dump_registers(&self) {
        println!("\ndump registers");
        for i in 0..REGISTERS_COUNT {
            println!("{} = {:#08X}", REGISTER_NAMES[i], self.registers[i]);
        }
        println!("EIP = {:#08X}", self.eip);
    }

    /// Emulate mov instruction.
    fn mov_r32_imm32(&mut self) {
        let index = self.get_code8(0) - 0xB8;
        let value = self.get_code32(1);
        self.registers[index as usize] = value;
        self.eip += 5u32;
    }

    /// Emulate short jump instruction.
    fn short_jump(&mut self) {
        let diff = self.get_code8(1) as i8;
        // Allow overflow
        self.eip = (Wrapping(self.eip) + Wrapping((diff + 2) as u32)).0;
    }
}
