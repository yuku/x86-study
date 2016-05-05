use std::io::Read;
use std::fs::File;
use std::num::Wrapping;

mod modrm;

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
    pub eip: u32,
    memory: [u8; MEMORY_SIZE],
}

impl Default for Emulator {
    fn default() -> Self {
        Emulator {
            registers: [0; REGISTERS_COUNT],
            eflags: Default::default(),
            eip: Default::default(),
            memory: [0; MEMORY_SIZE],
        }
    }
}

impl Emulator {
    pub fn new(eip: u32, esp: u32) -> Emulator {
        let mut emu = Emulator::default();
        emu.registers[ESP] = esp;
        emu.eip = eip;
        emu
    }

    pub fn load(&mut self, path: &str) {
        let mut f = File::open(path)
            .expect(&format!("failed to read {}", path));
        f.read(&mut self.memory[(self.eip as usize)..MEMORY_SIZE])
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

    pub fn get_code8(&self, index: u32) -> u8 {
        self.memory[(self.eip + index) as usize]
    }

    pub fn get_code32(&self, index: u32) -> u32 {
        let mut code = 0u32;
        for i in 0..4 {
            code |= (self.get_code8(index + i) as u32) << (i * 8);
        }
        code
    }

    fn execute(&mut self) {
        let code = self.get_code8(0);

        println!("EIP = 0x{eip:08X}, Code = 0x{code:08X}", eip = self.eip, code = code);

        match code {
            0x01 => self.add_rm32_r32(),
            0x83 => self.code_83(),
            0x89 => self.mov_rm32_r32(),
            0x8B => self.mov_r32_rm32(),
            0xB8...0xBF => self.mov_r32_imm32(),
            0xC7 => self.mov_rm32_imm32(),
            0xE9 => self.near_jump(),
            0xEB => self.short_jump(),
            _ => {
                self.dump_registers();
                panic!("not implemented");
            },
        }
    }

    fn dump_registers(&self) {
        println!("\ndump registers");
        for i in 0..REGISTERS_COUNT {
            println!("{} = 0x{:08X}", REGISTER_NAMES[i], self.registers[i]);
        }
        println!("EIP = 0x{:08X}", self.eip);
    }

    /// Emulate mov instruction.
    ///
    /// ```
    /// mov eax, 41
    /// ```
    fn mov_r32_imm32(&mut self) {
        let index = self.get_code8(0) - 0xB8;
        let value = self.get_code32(1);
        self.set_register32(index, value);
        self.eip += 5;
    }

    /// Emulate mov instruction.
    ///
    /// ```
    /// mov dword [ebp+4], 5
    /// ```
    fn mov_rm32_imm32(&mut self) {
        self.eip += 1;
        let modrm = modrm::ModRM::parse(self);
        let value = self.get_code32(0);
        self.eip += 4;
        self.set_rm32(&modrm, value);
    }

    /// Emulate mov instruction.
    ///
    /// ```
    /// mov dword [ebp+4], eax
    /// ```
    fn mov_rm32_r32(&mut self) {
        self.eip += 1;
        let modrm = modrm::ModRM::parse(self);
        let r32 = self.get_r32(&modrm);
        self.set_rm32(&modrm, r32);
    }

    /// Emulate mov instruction.
    ///
    /// ```
    /// mov esi, [ebp+4]
    /// ```
    fn mov_r32_rm32(&mut self) {
        self.eip += 1;
        let modrm = modrm::ModRM::parse(self);
        let rm32 = self.get_rm32(&modrm);
        self.set_r32(&modrm, rm32);
    }

    /// Emulate add instruction.
    ///
    /// ```
    /// add dword [ebp+4], eax
    /// ```
    fn add_rm32_r32(&mut self) {
        self.eip += 1;
        let modrm = modrm::ModRM::parse(self);
        let r32 = self.get_r32(&modrm);
        let rm32 = self.get_rm32(&modrm);
        self.set_rm32(&modrm, r32 + rm32);
    }

    fn code_83(&mut self) {
        self.eip += 1;
        let modrm = modrm::ModRM::parse(self);
        if modrm.reg == 5 {
            self.sub_rm32_imm8(&modrm);
        } else {
            panic!(format!("not implemented: 83 /{}", modrm.reg));
        }
    }

    fn sub_rm32_imm8(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm8 = self.get_code8(0) as u32;
        self.eip += 1;
        self.set_rm32(&modrm, rm32 - imm8);
    }

    /// Emulate short jump instruction.
    ///
    /// ```
    /// jmp short start
    /// ```
    fn short_jump(&mut self) {
        let diff = self.get_code8(1) as i8;
        // Allow overflow
        self.eip = (Wrapping(self.eip) + Wrapping((diff + 2) as u32)).0;
    }

    /// Emulate near jump instruction.
    ///
    /// ```
    /// jmp 0
    /// ```
    fn near_jump(&mut self) {
        let diff = self.get_code32(1) as i32;
        self.eip = (Wrapping(self.eip) + Wrapping((diff + 5) as u32)).0;
    }

    fn calc_memory_address(&self, modrm: &modrm::ModRM) -> u32 {
        if modrm.mod_ == 0 {
            match modrm.rm {
                4 => panic!("not implemented ModRM mod = 0, rm = 4"),
                5 => modrm.disp32,
                _ => self.get_register32(modrm.rm),
            }
        } else if modrm.mod_ == 1 {
            match modrm.rm {
                4 => panic!("not implemented ModRM mod = 1, rm = 4"),
                _ => self.get_register32(modrm.rm) + modrm.disp8 as u32,
            }
        } else if modrm.mod_ == 2 {
            match modrm.rm {
                4 => panic!("not implemented ModRM mod = 2, rm = 4"),
                _ => self.get_register32(modrm.rm) + modrm.disp32,
            }
        } else {
            panic!("not implemented ModRM mod = 3");
        }
    }

    fn get_register32(&self, index: u8) -> u32 {
        self.registers[index as usize]
    }

    fn set_register32(&mut self, index: u8, value: u32) {
        self.registers[index as usize] = value;
    }

    fn set_memory8(&mut self, address: u32, value: u8) {
        self.memory[address as usize] = value;
    }

    /// Set 32-bit value in little endian.
    fn set_memory32(&mut self, address: u32, value: u32) {
        for i in 0..4 {
            self.set_memory8(address + i, (value >> (i * 8)) as u8);
        }
    }

    fn get_memory8(&self, address: u32) -> u8 {
        self.memory[address as usize]
    }

    fn get_memory32(&self, address: u32) -> u32 {
        let mut ret = 0u32;
        for i in 0..4 {
            ret |= (self.get_memory8(address + i) as u32) << (i * 8);
        }
        ret
    }

    fn get_rm32(&self, modrm: &modrm::ModRM) -> u32 {
        if modrm.mod_ == 3 {
            self.get_register32(modrm.rm)
        } else {
            let address = self.calc_memory_address(modrm);
            self.get_memory32(address)
        }
    }

    fn set_rm32(&mut self, modrm: &modrm::ModRM, value: u32) {
        if modrm.mod_ == 3 {
            self.set_register32(modrm.rm, value);
        } else {
            let address = self.calc_memory_address(modrm);
            self.set_memory32(address, value);
        }
    }

    fn get_r32(&self, modrm: &modrm::ModRM) -> u32 {
        self.get_register32(modrm.reg)
    }

    fn set_r32(&mut self, modrm: &modrm::ModRM, value: u32) {
        self.set_register32(modrm.reg, value);
    }
}
