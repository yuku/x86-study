use emulator::Emulator;

#[allow(dead_code)]
#[derive(Default)]
pub struct ModRM {
    pub mod_: u8,
    pub reg: u8,
    pub rm: u8,
    sib: u8,
    pub disp8: i8,
    pub disp32: u32,
}

impl ModRM {
    pub fn parse(emu: &mut Emulator) -> ModRM {
        let code = emu.get_code8(0);

        let mut modrm = ModRM::default();
        modrm.mod_ = (code & 0xC0) >> 6;
        modrm.reg = (code & 0x38) >> 3;
        modrm.rm = code & 0x07;

        emu.eip += 1;

        if modrm.mod_ != 3 && modrm.rm == 4 {
            modrm.sib = emu.get_code8(0);
            emu.eip += 1;
        }
        if modrm.mod_ == 0 && modrm.rm == 5 || modrm.mod_ == 2 {
            modrm.disp32 = emu.get_code32(0);
            emu.eip += 4;
        } else if modrm.mod_ == 1 {
            modrm.disp8 = emu.get_code8(0) as i8;
            emu.eip += 1;
        }
        modrm
    }
}
