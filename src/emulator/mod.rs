use std::io::Read;
use std::fs::File;
use std::num::Wrapping;

mod modrm;

const REGISTERS_COUNT: usize = 8;
const REGISTER_NAMES: [&'static str; REGISTERS_COUNT] = [
    "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"
];
const EAX: usize = 0;
const ESP: usize = 4;
const EBP: usize = 5;
pub const OPCODE_LENGTH: u32 = 1;
const IMM32_LENGTH: u32 = 4;
const IMM8_LENGTH: u32 = 1;
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

        println!("EIP = 0x{:08X}, Code = 0x{:02X}", self.eip, code);

        match code {
            0x01 => self.add_rm32_r32(),
            0x03 => self.add_r32_rm32(),
            0x05 => self.add_eax_imm32(),
            0x09 => self.or_rm32_r32(),
            0x0B => self.or_r32_rm32(),
            0x0D => self.or_eax_imm32(),
            0x21 => self.and_rm32_r32(),
            0x23 => self.and_r32_rm32(),
            0x25 => self.and_eax_imm32(),
            0x29 => self.sub_rm32_r32(),
            0x2B => self.sub_r32_rm32(),
            0x2D => self.sub_eax_imm32(),
            0x31 => self.xor_rm32_r32(),
            0x33 => self.xor_r32_rm32(),
            0x35 => self.xor_eax_imm32(),
            0x39 => self.cmp_rm32_r32(),
            0x3B => self.cmp_r32_rm32(),
            0x3D => self.cmp_eax_imm32(),
            0x50...0x57 => self.push_r32(),
            0x58...0x5F => self.pop_r32(),
            0x68 => self.push_imm32(),
            0x6A => self.push_imm8(),
            0x70 => self.jo_rel8(),
            0x71 => self.jno_rel8(),
            0x72 => self.jc_rel8(),
            0x73 => self.jnc_rel8(),
            0x74 => self.jz_rel8(),
            0x75 => self.jnz_rel8(),
            0x78 => self.js_rel8(),
            0x79 => self.jns_rel8(),
            0x7C => self.jl_rel8(),
            //0x7D => self.jge_rel8(),
            0x7E => self.jle_rel8(),
            //0x7F => self.jg_rel8(),
            0x81 => {
                let modrm = modrm::ModRM::parse(self);
                match modrm.reg {
                    0 => self.add_rm32_imm32(&modrm),
                    1 => self.or_rm32_imm32(&modrm),
                    4 => self.and_rm32_imm32(&modrm),
                    5 => self.sub_rm32_imm32(&modrm),
                    6 => self.xor_rm32_imm32(&modrm),
                    7 => self.cmp_rm32_imm32(&modrm),
                    _ => panic!(format!("not implemented: 81 /{}", modrm.reg)),
                }
            },
            0x83 => {
                let modrm = modrm::ModRM::parse(self);
                match modrm.reg {
                    0 => self.add_rm32_imm8(&modrm),
                    1 => self.or_rm32_imm8(&modrm),
                    4 => self.and_rm32_imm8(&modrm),
                    5 => self.sub_rm32_imm8(&modrm),
                    6 => self.xor_rm32_imm8(&modrm),
                    7 => self.cmp_rm32_imm8(&modrm),
                    _ => panic!(format!("not implemented: 83 /{}", modrm.reg)),
                }
            },
            0x89 => self.mov_rm32_r32(),
            0x8B => self.mov_r32_rm32(),
            0x8D => self.lea_r32_m(),
            0xB8...0xBF => self.mov_r32_imm32(),
            0xC3 => self.ret(),
            0xC7 => self.mov_rm32_imm32(),
            0xC9 => self.leave(),
            0xE8 => self.call_rel32(),
            0xE9 => self.near_jump(),
            0xEB => self.short_jump(),
            0xF7 => {
                let modrm = modrm::ModRM::parse(self);
                match modrm.reg {
                    3 => self.neg_rm32(&modrm),
                    _ => panic!(format!("not implemented: F7 /{}", modrm.reg)),
                }
            },
            0xFF => {
                let modrm = modrm::ModRM::parse(self);
                match modrm.reg {
                    0 => self.inc_rm32(&modrm),
                    _ => panic!(format!("not implemented: FF /{}", modrm.reg)),
                }
            },
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

    /// 01 /r sz : add r/m32 r32
    fn add_rm32_r32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let rm32 = self.get_rm32(&modrm);
        let r32 = self.get_r32(&modrm);
        let result = (Wrapping(rm32 as u64) + Wrapping(r32 as u64)).0;
        self.set_rm32(&modrm, result as u32);
        self.update_eflags(rm32, r32, result);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 03 /r sz : add r32 r/m32
    fn add_r32_rm32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let r32 = self.get_r32(&modrm);
        let rm32 = self.get_rm32(&modrm);
        let result = (Wrapping(r32 as u64) + Wrapping(rm32 as u64)).0;
        self.set_r32(&modrm, result as u32);
        self.update_eflags(rm32, r32, result);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 05 id sz : add eax imm32
    fn add_eax_imm32(&mut self) {
        let eax = self.get_register32(EAX as u8);
        let imm32 = self.get_code32(OPCODE_LENGTH);
        let result = (Wrapping(eax as u64) + Wrapping(imm32 as u64)).0;
        self.set_register32(EAX as u8, result as u32);
        self.update_eflags(eax, imm32, result);
        self.eip += OPCODE_LENGTH + IMM32_LENGTH;
    }

    /// 09 /r rz : or r/m32 r32
    fn or_rm32_r32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let rm32 = self.get_rm32(&modrm);
        let r32 = self.get_r32(&modrm);
        self.set_rm32(&modrm, rm32 | r32);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 0B /r sz : or r32 r/m32
    fn or_r32_rm32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let r32 = self.get_r32(&modrm);
        let rm32 = self.get_rm32(&modrm);
        self.set_r32(&modrm, r32 | rm32);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 0D id sz : or eax imm32
    fn or_eax_imm32(&mut self) {
        let eax = self.get_register32(EAX as u8);
        let imm32 = self.get_code32(OPCODE_LENGTH);
        self.set_register32(EAX as u8, eax | imm32);
        self.eip += OPCODE_LENGTH + IMM32_LENGTH;
    }

    /// 21 /r sz : and r/m32 r32
    fn and_rm32_r32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let rm32 = self.get_rm32(&modrm);
        let r32 = self.get_r32(&modrm);
        self.set_rm32(&modrm, rm32 & r32);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 23 /r sz : and r32 r/m32
    fn and_r32_rm32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let r32 = self.get_r32(&modrm);
        let rm32 = self.get_rm32(&modrm);
        self.set_r32(&modrm, r32 & rm32);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 25 id sz : and eax imm32
    fn and_eax_imm32(&mut self) {
        let eax = self.get_register32(EAX as u8);
        let imm32 = self.get_code32(OPCODE_LENGTH);
        self.set_register32(EAX as u8, eax & imm32);
        self.eip += OPCODE_LENGTH + IMM32_LENGTH;
    }

    /// 29 /r sz : sub r/m32 r32
    fn sub_rm32_r32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let rm32 = self.get_rm32(&modrm);
        let r32 = self.get_r32(&modrm);
        let result = (Wrapping(rm32 as u64) - Wrapping(r32 as u64)).0;
        self.set_rm32(&modrm, result as u32);
        self.update_eflags(rm32, r32, result);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 2B /r sz : sub r32 r/m32
    fn sub_r32_rm32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let r32 = self.get_r32(&modrm);
        let rm32 = self.get_rm32(&modrm);
        let result = (Wrapping(r32 as u64) - Wrapping(rm32 as u64)).0;
        self.set_r32(&modrm, result as u32);
        self.update_eflags(r32, rm32, result);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 2D id sz : sub eax imm32
    fn sub_eax_imm32(&mut self) {
        let eax = self.get_register32(EAX as u8);
        let imm32 = self.get_code32(OPCODE_LENGTH);
        let result = (Wrapping(eax as u64) - Wrapping(imm32 as u64)).0;
        self.set_register32(EAX as u8, result as u32);
        self.update_eflags(eax, imm32, result);
        self.eip += OPCODE_LENGTH + IMM32_LENGTH;
    }

    /// 31 /r sz : xor r/m32 r32
    fn xor_rm32_r32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let rm32 = self.get_rm32(&modrm);
        let r32 = self.get_r32(&modrm);
        self.set_rm32(&modrm, rm32 ^ r32);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 33 /r sz : xor r32 r/m32
    fn xor_r32_rm32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let r32 = self.get_r32(&modrm);
        let rm32 = self.get_rm32(&modrm);
        self.set_rm32(&modrm, r32 ^ rm32);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 35 /r sz : xor eax imm32
    fn xor_eax_imm32(&mut self) {
        let eax = self.get_register32(EAX as u8);
        let imm32 = self.get_code32(OPCODE_LENGTH);
        self.set_register32(EAX as u8, eax ^ imm32);
        self.eip += OPCODE_LENGTH + IMM32_LENGTH;
    }

    /// 39 /r sz : cmp r/m32 r32
    fn cmp_rm32_r32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let rm32 = self.get_rm32(&modrm);
        let r32 = self.get_r32(&modrm);
        let result = (Wrapping(rm32 as u64) - Wrapping(r32 as u64)).0;
        self.update_eflags(rm32, r32, result);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 3B /r sz : cmp r32 r/m32
    fn cmp_r32_rm32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let r32 = self.get_r32(&modrm);
        let rm32 = self.get_rm32(&modrm);
        let result = (Wrapping(r32 as u64) - Wrapping(rm32 as u64)).0;
        self.update_eflags(r32, rm32, result);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 3D id sz : cmp eax imm32
    fn cmp_eax_imm32(&mut self) {
        let eax = self.get_register32(EAX as u8);
        let imm32 = self.get_code32(OPCODE_LENGTH);
        let result = (Wrapping(eax as u64) - Wrapping(imm32 as u64)).0;
        self.update_eflags(eax, imm32, result);
        self.eip += OPCODE_LENGTH + IMM32_LENGTH;
    }

    /// 50 sz : push eax
    /// 51 sz : push ecx
    /// 52 sz : push edx
    /// 53 sz : push ebx
    /// 54 sz : push esp
    /// 55 sz : push ebp
    /// 56 sz : push esi
    /// 57 sz : push edi
    fn push_r32(&mut self) {
        let index = self.get_code8(0) - 0x50;
        let value = self.get_register32(index);
        self.push32(value);
        self.eip += OPCODE_LENGTH;
    }

    /// 58 sz : pop eax
    /// 59 sz : pop ecx
    /// 5A sz : pop edx
    /// 5B sz : pop ebx
    /// 5C sz : pop esp
    /// 5D sz : pop ebp
    /// 5E sz : pop esi
    /// 5F sz : pop edi
    fn pop_r32(&mut self) {
        let index = self.get_code8(0) - 0x58;
        let value = self.pop32();
        self.set_register32(index, value);
        self.eip += OPCODE_LENGTH;
    }

    /// 68 id sz : push imm32
    fn push_imm32(&mut self) {
        let imm32 = self.get_code32(OPCODE_LENGTH);
        self.push32(imm32);
        self.eip += OPCODE_LENGTH + IMM32_LENGTH;
    }

    /// 6A ib : push imm8
    fn push_imm8(&mut self) {
        let imm8 = self.get_code8(OPCODE_LENGTH);
        self.push32(imm8 as u32);
        self.eip += OPCODE_LENGTH + IMM8_LENGTH;
    }

    /// 70 cb : jo rel8
    fn jo_rel8(&mut self) {
        let diff = if self.is_overflow() { self.get_code8(OPCODE_LENGTH) } else { 0 } as u32;
        self.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
    }

    /// 71 cb : jno rel8
    fn jno_rel8(&mut self) {
        let diff = if self.is_overflow() { 0 } else { self.get_code8(OPCODE_LENGTH) } as u32;
        self.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
    }

    /// 72 cb : jc rel8
    fn jc_rel8(&mut self) {
        let diff = if self.is_carry() { self.get_code8(OPCODE_LENGTH) } else { 0 } as u32;
        self.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
    }

    /// 73 cb : jnc rel8
    fn jnc_rel8(&mut self) {
        let diff = if self.is_carry() { 0 } else { self.get_code8(OPCODE_LENGTH) } as u32;
        self.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
    }

    /// 74 cb : jz rel8
    fn jz_rel8(&mut self) {
        let diff = if self.is_zero() { self.get_code8(OPCODE_LENGTH) } else { 0 } as u32;
        self.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
    }

    /// 75 cb : jnz rel8
    fn jnz_rel8(&mut self) {
        let diff = if self.is_zero() { 0 } else { self.get_code8(OPCODE_LENGTH) } as u32;
        self.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
    }

    /// 78 cb : js rel8
    fn js_rel8(&mut self) {
        let diff = if self.is_sign() { self.get_code8(OPCODE_LENGTH) } else { 0 } as u32;
        self.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
    }

    /// 79 cb : jns rel8
    fn jns_rel8(&mut self) {
        let diff = if self.is_sign() { 0 } else { self.get_code8(OPCODE_LENGTH) } as u32;
        self.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
    }

    /// 7C cb : jl rel8
    fn jl_rel8(&mut self) {
        let diff = if self.is_sign() != self.is_overflow() {
            self.get_code8(OPCODE_LENGTH)
        } else {
            0
        } as u32;
        self.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
    }

    /// 7D cb : jge rel8

    /// 7E cb : jle rel8
    fn jle_rel8(&mut self) {
        let diff = if self.is_zero() || self.is_sign() != self.is_overflow() {
            self.get_code8(OPCODE_LENGTH)
        } else {
            0
        } as u32;
        self.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
    }

    /// 7F cb : jg rel8

    /// 81 /0 id sz : add r/m32 imm32
    fn add_rm32_imm32(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm32 = self.get_code32(OPCODE_LENGTH + modrm.length);
        let result = (Wrapping(rm32 as u64) + Wrapping(imm32 as u64)).0;
        self.set_rm32(&modrm, result as u32);
        self.update_eflags(rm32, imm32, result);
        self.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
    }

    /// 81 /1 id sz : or r/m32 imm32
    fn or_rm32_imm32(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm32 = self.get_code32(OPCODE_LENGTH + modrm.length);
        self.set_rm32(&modrm, rm32 | imm32);
        self.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
    }

    /// 81 /4 id sz : and r/m32 imm32
    fn and_rm32_imm32(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm32 = self.get_code32(OPCODE_LENGTH + modrm.length);
        self.set_rm32(&modrm, rm32 & imm32);
        self.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
    }

    /// 81 /5 id sz : sub r/m32 imm32
    fn sub_rm32_imm32(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm32 = self.get_code32(OPCODE_LENGTH + modrm.length);
        let result = (Wrapping(rm32 as u64) - Wrapping(imm32 as u64)).0;
        self.set_rm32(&modrm, result as u32);
        self.update_eflags(rm32, imm32, result);
        self.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
    }

    /// 81 /6 id sz : xor r/m32 imm32
    fn xor_rm32_imm32(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm32 = self.get_code32(OPCODE_LENGTH + modrm.length);
        self.set_rm32(&modrm, rm32 ^ imm32);
        self.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
    }

    /// 81 /7 ib : cmp r/m32 imm32
    fn cmp_rm32_imm32(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm32 = self.get_code32(OPCODE_LENGTH + modrm.length);
        let result = (Wrapping(rm32 as u64) - Wrapping(imm32 as u64)).0;
        self.update_eflags(rm32, imm32, result);
        self.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
    }

    /// 83 /0 ib sz : add r/m32 imm8
    fn add_rm32_imm8(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm8 = self.get_code8(OPCODE_LENGTH + modrm.length) as u32;
        let result = (Wrapping(rm32 as u64) + Wrapping(imm8 as u64)).0;
        self.set_rm32(&modrm, result as u32);
        self.update_eflags(rm32, imm8, result);
        self.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
    }

    /// 83 /1 ib sz : or r/m32 imm8
    fn or_rm32_imm8(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm8 = self.get_code8(OPCODE_LENGTH + modrm.length) as u32;
        self.set_rm32(&modrm, rm32 | imm8);
        self.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
    }

    /// 83 /4 ib sz : and r/m32 imm8
    fn and_rm32_imm8(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm8 = self.get_code8(OPCODE_LENGTH + modrm.length) as u32;
        self.set_rm32(&modrm, rm32 & imm8);
        self.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
    }

    /// 83 /5 ib sz : sub r/m32 imm8
    fn sub_rm32_imm8(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm8 = self.get_code8(OPCODE_LENGTH + modrm.length) as u32;
        let result = (Wrapping(rm32 as u64) - Wrapping(imm8 as u64)).0;
        self.set_rm32(&modrm, result as u32);
        self.update_eflags(rm32, imm8, result);
        self.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
    }

    /// 83 /6 ib sz : xor r/m32 imm8
    fn xor_rm32_imm8(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm8 = self.get_code8(OPCODE_LENGTH + modrm.length) as u32;
        self.set_rm32(&modrm, rm32 ^ imm8);
        self.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
    }

    /// 83 /7 ib : cmp r/m32 imm8
    fn cmp_rm32_imm8(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        let imm8 = self.get_code8(OPCODE_LENGTH + modrm.length) as u32;
        let result = (Wrapping(rm32 as u64) - Wrapping(imm8 as u64)).0;
        self.update_eflags(rm32, imm8, result);
        self.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
    }

    /// 89 /r sz : mov r/m32 r32
    fn mov_rm32_r32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let r32 = self.get_r32(&modrm);
        self.set_rm32(&modrm, r32);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 8B /r sz : mov r32 r/m32
    fn mov_r32_rm32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let rm32 = self.get_rm32(&modrm);
        self.set_r32(&modrm, rm32);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// 8D /r sz : lea r32 m
    fn lea_r32_m(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let address = self.calc_memory_address(&modrm);
        self.set_r32(&modrm, address);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// B8 id sz : mov eax imm32
    /// B9 id sz : mov ecx imm32
    /// BA id sz : mov edx imm32
    /// BB id sz : mov ebx imm32
    /// BC id sz : mov esp imm32
    /// BD id sz : mov ebp imm32
    /// BE id sz : mov esi imm32
    /// BF id sz : mov edi imm32
    fn mov_r32_imm32(&mut self) {
        let index = self.get_code8(0) - 0xB8;
        let imm32 = self.get_code32(OPCODE_LENGTH);
        self.set_register32(index, imm32);
        self.eip += OPCODE_LENGTH + IMM32_LENGTH;
    }

    /// C3 : ret
    fn ret(&mut self) {
        self.eip = self.pop32();
    }

    /// C7 /0 id sz : mov r/m32 imm32
    fn mov_rm32_imm32(&mut self) {
        let modrm = modrm::ModRM::parse(self);
        let imm32 = self.get_code32(OPCODE_LENGTH + modrm.length);
        self.set_rm32(&modrm, imm32);
        self.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
    }

    /// C9 : leave
    fn leave(&mut self) {
        let ebp = self.get_register32(EBP as u8);
        self.set_register32(ESP as u8, ebp);
        let value = self.pop32();
        self.set_register32(EBP as u8, value);
        self.eip += OPCODE_LENGTH;
    }

    /// E8 cd : call rel32
    fn call_rel32(&mut self) {
        let diff = self.get_code32(OPCODE_LENGTH) as u32;
        let value = self.eip + OPCODE_LENGTH + IMM32_LENGTH;
        self.push32(value);
        self.eip = (Wrapping(value) + Wrapping(diff)).0;
    }

    /// E9 cd : jmp rel16
    /// E9 cd : jmp rel32
    fn near_jump(&mut self) {
        let diff = self.get_code32(OPCODE_LENGTH) as u32;
        self.eip = (Wrapping(self.eip) + Wrapping((diff + OPCODE_LENGTH + IMM32_LENGTH) as u32)).0;
    }

    /// EB cd : jmp rel8
    fn short_jump(&mut self) {
        let diff = self.get_code8(OPCODE_LENGTH) as u32;
        self.eip = (Wrapping(self.eip) + Wrapping((diff + OPCODE_LENGTH + IMM8_LENGTH) as u32)).0;
    }

    /// F7 /3 sz : neg r/m32
    fn neg_rm32(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm) as i32;
        self.set_rm32(&modrm, -rm32 as u32);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    /// FF /0 sz : inc r/m32
    fn inc_rm32(&mut self, modrm: &modrm::ModRM) {
        let rm32 = self.get_rm32(&modrm);
        self.set_rm32(&modrm, rm32 + 1);
        self.eip += OPCODE_LENGTH + modrm.length;
    }

    fn calc_memory_address(&self, modrm: &modrm::ModRM) -> u32 {
        if modrm.mod_ == 0 {
            match modrm.rm {
                4 => self.eval_sib(&modrm),
                5 => modrm.disp32,
                _ => self.get_register32(modrm.rm),
            }
        } else if modrm.mod_ == 1 {
            match modrm.rm {
                4 => (Wrapping(self.eval_sib(&modrm)) + Wrapping(modrm.disp8 as u32)).0,
                _ => (Wrapping(self.get_register32(modrm.rm)) + Wrapping(modrm.disp8 as u32)).0,
            }
        } else if modrm.mod_ == 2 {
            match modrm.rm {
                4 => (Wrapping(self.eval_sib(&modrm)) + Wrapping(modrm.disp32)).0,
                _ => (Wrapping(self.get_register32(modrm.rm)) + Wrapping(modrm.disp32)).0,
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

    fn push32(&mut self, value: u32) {
        let address = self.get_register32(ESP as u8) - 4;
        self.set_register32(ESP as u8, address);
        self.set_memory32(address, value);
    }

    fn pop32(&mut self) -> u32 {
        let address = self.get_register32(ESP as u8);
        let ret = self.get_memory32(address);
        self.set_register32(ESP as u8, address + 4);
        ret
    }

    fn eval_sib(&self, modrm: &modrm::ModRM) -> u32 {
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

    fn update_eflags(&mut self, v1: u32, v2: u32, result: u64) {
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

    fn is_carry(&self) -> bool {
        self.eflags & CARRY_FLAG != 0
    }

    fn is_zero(&self) -> bool {
        self.eflags & ZERO_FLAG != 0
    }

    fn is_sign(&self) -> bool {
        self.eflags & SIGN_FLAG != 0
    }

    fn is_overflow(&self) -> bool {
        self.eflags & OVERFLOW_FLAG != 0
    }
}
