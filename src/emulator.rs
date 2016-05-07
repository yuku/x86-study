use std::io::Read;
use std::fs::File;

use modrm;
use instructions;

const REGISTERS_COUNT: usize = 8;
const REGISTER_NAMES: [&'static str; REGISTERS_COUNT] = [
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"
];
pub const EAX: usize = 0;
pub const ESP: usize = 4;
pub const EBP: usize = 5;
const MEMORY_SIZE: usize = 1024 * 1024;
const CARRY_FLAG: u32 = 1 << 0;
const ZERO_FLAG: u32 = 1 << 6;
const SIGN_FLAG: u32 = 1 << 7;
const OVERFLOW_FLAG: u32 = 1 << 11;

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

        println!("EIP = 0x{:08X}, Code = 0x{:02X}", self.eip, code);

        match code {
            0x01 => instructions::add_rm32_r32(self),
            0x03 => instructions::add_r32_rm32(self),
            0x05 => instructions::add_eax_imm32(self),
            0x09 => instructions::or_rm32_r32(self),
            0x0B => instructions::or_r32_rm32(self),
            0x0D => instructions::or_eax_imm32(self),
            0x21 => instructions::and_rm32_r32(self),
            0x23 => instructions::and_r32_rm32(self),
            0x25 => instructions::and_eax_imm32(self),
            0x29 => instructions::sub_rm32_r32(self),
            0x2B => instructions::sub_r32_rm32(self),
            0x2D => instructions::sub_eax_imm32(self),
            0x31 => instructions::xor_rm32_r32(self),
            0x33 => instructions::xor_r32_rm32(self),
            0x35 => instructions::xor_eax_imm32(self),
            0x39 => instructions::cmp_rm32_r32(self),
            0x3B => instructions::cmp_r32_rm32(self),
            0x3D => instructions::cmp_eax_imm32(self),
            0x50...0x57 => instructions::push_r32(self),
            0x58...0x5F => instructions::pop_r32(self),
            0x68 => instructions::push_imm32(self),
            0x6A => instructions::push_imm8(self),
            0x70 => instructions::jo_rel8(self),
            0x71 => instructions::jno_rel8(self),
            0x72 => instructions::jc_rel8(self),
            0x73 => instructions::jnc_rel8(self),
            0x74 => instructions::jz_rel8(self),
            0x75 => instructions::jnz_rel8(self),
            0x78 => instructions::js_rel8(self),
            0x79 => instructions::jns_rel8(self),
            0x7C => instructions::jl_rel8(self),
            0x7D => instructions::jge_rel8(self),
            0x7E => instructions::jle_rel8(self),
            0x7F => instructions::jg_rel8(self),
            0x81 => {
                let modrm = modrm::ModRM::parse(self);
                match modrm.reg {
                    0 => instructions::add_rm32_imm32(self, &modrm),
                    1 => instructions::or_rm32_imm32(self, &modrm),
                    4 => instructions::and_rm32_imm32(self, &modrm),
                    5 => instructions::sub_rm32_imm32(self, &modrm),
                    6 => instructions::xor_rm32_imm32(self, &modrm),
                    7 => instructions::cmp_rm32_imm32(self, &modrm),
                    _ => panic!(format!("not implemented: 81 /{}", modrm.reg)),
                }
            },
            0x83 => {
                let modrm = modrm::ModRM::parse(self);
                match modrm.reg {
                    0 => instructions::add_rm32_imm8(self, &modrm),
                    1 => instructions::or_rm32_imm8(self, &modrm),
                    4 => instructions::and_rm32_imm8(self, &modrm),
                    5 => instructions::sub_rm32_imm8(self, &modrm),
                    6 => instructions::xor_rm32_imm8(self, &modrm),
                    7 => instructions::cmp_rm32_imm8(self, &modrm),
                    _ => panic!(format!("not implemented: 83 /{}", modrm.reg)),
                }
            },
            0x89 => instructions::mov_rm32_r32(self),
            0x8B => instructions::mov_r32_rm32(self),
            0x8D => instructions::lea_r32_m(self),
            0x90 => instructions::nop(self),
            0xB8...0xBF => instructions::mov_r32_imm32(self),
            0xC3 => instructions::ret(self),
            0xC7 => instructions::mov_rm32_imm32(self),
            0xC9 => instructions::leave(self),
            0xE8 => instructions::call_rel32(self),
            0xE9 => instructions::near_jump(self),
            0xEB => instructions::short_jump(self),
            0xF7 => {
                let modrm = modrm::ModRM::parse(self);
                match modrm.reg {
                    3 => instructions::neg_rm32(self, &modrm),
                    _ => panic!(format!("not implemented: F7 /{}", modrm.reg)),
                }
            },
            0xFF => {
                let modrm = modrm::ModRM::parse(self);
                match modrm.reg {
                    0 => instructions::inc_rm32(self, &modrm),
                    _ => panic!(format!("not implemented: FF /{}", modrm.reg)),
                }
            },
            _ => {
                panic!("not implemented");
            },
        }
    }

    pub fn dump_registers(&self) {
        println!("\ndump registers");
        for i in 0..REGISTERS_COUNT {
            println!("{} = 0x{:08X}", REGISTER_NAMES[i], self.registers[i]);
        }
        println!("EIP = 0x{:08X}", self.eip);
    }

    pub fn get_register32(&self, index: u8) -> u32 {
        self.registers[index as usize]
    }

    pub fn set_register32(&mut self, index: u8, value: u32) {
        self.registers[index as usize] = value;
    }

    pub fn set_memory8(&mut self, address: u32, value: u8) {
        self.memory[address as usize] = value;
    }

    /// Set 32-bit value in little endian.
    pub fn set_memory32(&mut self, address: u32, value: u32) {
        for i in 0..4 {
            self.set_memory8(address + i, (value >> (i * 8)) as u8);
        }
    }

    pub fn get_memory8(&self, address: u32) -> u8 {
        self.memory[address as usize]
    }

    pub fn get_memory32(&self, address: u32) -> u32 {
        let mut ret = 0u32;
        for i in 0..4 {
            ret |= (self.get_memory8(address + i) as u32) << (i * 8);
        }
        ret
    }

    pub fn get_rm32(&self, modrm: &modrm::ModRM) -> u32 {
        if modrm.mod_ == 3 {
            self.get_register32(modrm.rm)
        } else {
            let address = modrm.calc_memory_address(self);
            self.get_memory32(address)
        }
    }

    pub fn set_rm32(&mut self, modrm: &modrm::ModRM, value: u32) {
        if modrm.mod_ == 3 {
            self.set_register32(modrm.rm, value);
        } else {
            let address = modrm.calc_memory_address(self);
            self.set_memory32(address, value);
        }
    }

    pub fn get_r32(&self, modrm: &modrm::ModRM) -> u32 {
        self.get_register32(modrm.reg)
    }

    pub fn set_r32(&mut self, modrm: &modrm::ModRM, value: u32) {
        self.set_register32(modrm.reg, value);
    }

    pub fn push32(&mut self, value: u32) {
        let address = self.get_register32(ESP as u8) - 4;
        self.set_register32(ESP as u8, address);
        self.set_memory32(address, value);
    }

    pub fn pop32(&mut self) -> u32 {
        let address = self.get_register32(ESP as u8);
        let ret = self.get_memory32(address);
        self.set_register32(ESP as u8, address + 4);
        ret
    }

    pub fn eval_sib(&self, modrm: &modrm::ModRM) -> u32 {
        let scale = (modrm.sib & 0xC0) >> 6;
        let index = (modrm.sib & 0x38) >> 3;
        let base = modrm.sib & 0x07;
        let r32b = if base == 5 { 0 } else { self.get_register32(base) };
        let r32i = if index == 4 { 0 } else { self.get_register32(index) };
        match scale {
            0 => r32b + r32i,
            1 => r32b + r32i * 2,
            2 => r32b + r32i * 4,
            _ => r32b + r32i * 8,
        }
    }

    pub fn update_eflags(&mut self, v1: u32, v2: u32, result: u64) {
        let sign1 = v1 >> 31;
        let sign2 = v2 >> 31;
        let signr = ((result >> 31) & 1) as u32;

        self.set_carry_flag((result >> 32) != 0);
        self.set_zero_flag(result == 0);
        self.set_sign_flag(signr != 0);
        self.set_overflow_flag(sign1 != sign2 && sign1 != signr);
    }

    fn set_carry_flag(&mut self, is_carry: bool) {
        if is_carry {
            self.eflags |= CARRY_FLAG;
        } else {
            self.eflags &= !CARRY_FLAG;
        }
    }

    fn set_zero_flag(&mut self, is_zero: bool) {
        if is_zero {
            self.eflags |= ZERO_FLAG;
        } else {
            self.eflags &= !ZERO_FLAG;
        }
    }

    fn set_sign_flag(&mut self, is_sign: bool) {
        if is_sign {
            self.eflags |= SIGN_FLAG;
        } else {
            self.eflags &= !SIGN_FLAG;
        }
    }

    fn set_overflow_flag(&mut self, is_overflow: bool) {
        if is_overflow {
            self.eflags |= OVERFLOW_FLAG;
        } else {
            self.eflags &= !OVERFLOW_FLAG;
        }
    }

    pub fn is_carry(&self) -> bool {
        self.eflags & CARRY_FLAG != 0
    }

    pub fn is_zero(&self) -> bool {
        self.eflags & ZERO_FLAG != 0
    }

    pub fn is_sign(&self) -> bool {
        self.eflags & SIGN_FLAG != 0
    }

    pub fn is_overflow(&self) -> bool {
        self.eflags & OVERFLOW_FLAG != 0
    }
}
