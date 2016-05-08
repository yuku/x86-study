use emulator;
use instructions;
use std::num::Wrapping;

#[allow(dead_code)]
#[derive(Default)]
pub struct ModRM {
    pub mod_: u8,
    pub reg: u8,
    pub rm: u8,
    pub sib: u8,
    pub disp8: i8,
    pub disp32: u32,
    pub length: u32,
}

impl ModRM {
    pub fn parse32(emu: &mut emulator::Emulator) -> ModRM {
        let code = emu.get_code8(instructions::OPCODE_LENGTH);

        let mut modrm = ModRM::default();
        modrm.mod_ = (code & 0xC0) >> 6;
        modrm.reg = (code & 0x38) >> 3;
        modrm.rm = code & 0x07;

        modrm.length += 1;

        if modrm.mod_ != 3 && modrm.rm == 4 {
            modrm.sib = emu.get_code8(instructions::OPCODE_LENGTH + modrm.length);
            modrm.length += 1;
        }
        if modrm.mod_ == 0 && modrm.rm == 5 || modrm.mod_ == 2 {
            modrm.disp32 = emu.get_code32(instructions::OPCODE_LENGTH + modrm.length);
            modrm.length += 4;
        } else if modrm.mod_ == 1 {
            modrm.disp8 = emu.get_code8(instructions::OPCODE_LENGTH + modrm.length) as i8;
            modrm.length += 1;
        }
        modrm
    }

    pub fn calc_memory_address32(&self, emu: &emulator::Emulator) -> u32 {
        if self.mod_ == 0 {
            match self.rm {
                4 => emu.eval_sib(&self),
                5 => self.disp32,
                _ => emu.get_register32(self.rm),
            }
        } else if self.mod_ == 1 {
            match self.rm {
                4 => (Wrapping(emu.eval_sib(&self)) + Wrapping(self.disp8 as u32)).0,
                _ => (Wrapping(emu.get_register32(self.rm)) + Wrapping(self.disp8 as u32)).0,
            }
        } else if self.mod_ == 2 {
            match self.rm {
                4 => (Wrapping(emu.eval_sib(&self)) + Wrapping(self.disp32)).0,
                _ => (Wrapping(emu.get_register32(self.rm)) + Wrapping(self.disp32)).0,
            }
        } else {
            panic!("not implemented self mod = 3");
        }
    }
}
