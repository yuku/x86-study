use emulator::EAX;
use emulator::EBP;
use emulator::ESP;
use emulator;
use modrm;
use std::num::Wrapping;

pub const OPCODE_LENGTH: u32 = 1;
const IMM32_LENGTH: u32 = 4;
const IMM8_LENGTH: u32 = 1;

/// 01 /r sz : add r/m32 r32
pub fn add_rm32_r32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let rm32 = emu.get_rm32(&modrm);
    let r32 = emu.get_r32(&modrm);
    let result = (Wrapping(rm32 as u64) + Wrapping(r32 as u64)).0;
    emu.set_rm32(&modrm, result as u32);
    emu.update_eflags(rm32, r32, result);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 03 /r sz : add r32 r/m32
pub fn add_r32_rm32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let r32 = emu.get_r32(&modrm);
    let rm32 = emu.get_rm32(&modrm);
    let result = (Wrapping(r32 as u64) + Wrapping(rm32 as u64)).0;
    emu.set_r32(&modrm, result as u32);
    emu.update_eflags(rm32, r32, result);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 05 id sz : add eax imm32
pub fn add_eax_imm32(emu: &mut emulator::Emulator) {
    let eax = emu.get_register32(EAX as u8);
    let imm32 = emu.get_code32(OPCODE_LENGTH);
    let result = (Wrapping(eax as u64) + Wrapping(imm32 as u64)).0;
    emu.set_register32(EAX as u8, result as u32);
    emu.update_eflags(eax, imm32, result);
    emu.eip += OPCODE_LENGTH + IMM32_LENGTH;
}

/// 09 /r rz : or r/m32 r32
pub fn or_rm32_r32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let rm32 = emu.get_rm32(&modrm);
    let r32 = emu.get_r32(&modrm);
    emu.set_rm32(&modrm, rm32 | r32);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 0B /r sz : or r32 r/m32
pub fn or_r32_rm32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let r32 = emu.get_r32(&modrm);
    let rm32 = emu.get_rm32(&modrm);
    emu.set_r32(&modrm, r32 | rm32);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 0D id sz : or eax imm32
pub fn or_eax_imm32(emu: &mut emulator::Emulator) {
    let eax = emu.get_register32(EAX as u8);
    let imm32 = emu.get_code32(OPCODE_LENGTH);
    emu.set_register32(EAX as u8, eax | imm32);
    emu.eip += OPCODE_LENGTH + IMM32_LENGTH;
}

/// 21 /r sz : and r/m32 r32
pub fn and_rm32_r32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let rm32 = emu.get_rm32(&modrm);
    let r32 = emu.get_r32(&modrm);
    emu.set_rm32(&modrm, rm32 & r32);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 23 /r sz : and r32 r/m32
pub fn and_r32_rm32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let r32 = emu.get_r32(&modrm);
    let rm32 = emu.get_rm32(&modrm);
    emu.set_r32(&modrm, r32 & rm32);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 25 id sz : and eax imm32
pub fn and_eax_imm32(emu: &mut emulator::Emulator) {
    let eax = emu.get_register32(EAX as u8);
    let imm32 = emu.get_code32(OPCODE_LENGTH);
    emu.set_register32(EAX as u8, eax & imm32);
    emu.eip += OPCODE_LENGTH + IMM32_LENGTH;
}

/// 29 /r sz : sub r/m32 r32
pub fn sub_rm32_r32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let rm32 = emu.get_rm32(&modrm);
    let r32 = emu.get_r32(&modrm);
    let result = (Wrapping(rm32 as u64) - Wrapping(r32 as u64)).0;
    emu.set_rm32(&modrm, result as u32);
    emu.update_eflags(rm32, r32, result);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 2B /r sz : sub r32 r/m32
pub fn sub_r32_rm32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let r32 = emu.get_r32(&modrm);
    let rm32 = emu.get_rm32(&modrm);
    let result = (Wrapping(r32 as u64) - Wrapping(rm32 as u64)).0;
    emu.set_r32(&modrm, result as u32);
    emu.update_eflags(r32, rm32, result);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 2D id sz : sub eax imm32
pub fn sub_eax_imm32(emu: &mut emulator::Emulator) {
    let eax = emu.get_register32(EAX as u8);
    let imm32 = emu.get_code32(OPCODE_LENGTH);
    let result = (Wrapping(eax as u64) - Wrapping(imm32 as u64)).0;
    emu.set_register32(EAX as u8, result as u32);
    emu.update_eflags(eax, imm32, result);
    emu.eip += OPCODE_LENGTH + IMM32_LENGTH;
}

/// 31 /r sz : xor r/m32 r32
pub fn xor_rm32_r32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let rm32 = emu.get_rm32(&modrm);
    let r32 = emu.get_r32(&modrm);
    emu.set_rm32(&modrm, rm32 ^ r32);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 33 /r sz : xor r32 r/m32
pub fn xor_r32_rm32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let r32 = emu.get_r32(&modrm);
    let rm32 = emu.get_rm32(&modrm);
    emu.set_rm32(&modrm, r32 ^ rm32);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 35 /r sz : xor eax imm32
pub fn xor_eax_imm32(emu: &mut emulator::Emulator) {
    let eax = emu.get_register32(EAX as u8);
    let imm32 = emu.get_code32(OPCODE_LENGTH);
    emu.set_register32(EAX as u8, eax ^ imm32);
    emu.eip += OPCODE_LENGTH + IMM32_LENGTH;
}

/// 39 /r sz : cmp r/m32 r32
pub fn cmp_rm32_r32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let rm32 = emu.get_rm32(&modrm);
    let r32 = emu.get_r32(&modrm);
    let result = (Wrapping(rm32 as u64) - Wrapping(r32 as u64)).0;
    emu.update_eflags(rm32, r32, result);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 3B /r sz : cmp r32 r/m32
pub fn cmp_r32_rm32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let r32 = emu.get_r32(&modrm);
    let rm32 = emu.get_rm32(&modrm);
    let result = (Wrapping(r32 as u64) - Wrapping(rm32 as u64)).0;
    emu.update_eflags(r32, rm32, result);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 3D id sz : cmp eax imm32
pub fn cmp_eax_imm32(emu: &mut emulator::Emulator) {
    let eax = emu.get_register32(EAX as u8);
    let imm32 = emu.get_code32(OPCODE_LENGTH);
    let result = (Wrapping(eax as u64) - Wrapping(imm32 as u64)).0;
    emu.update_eflags(eax, imm32, result);
    emu.eip += OPCODE_LENGTH + IMM32_LENGTH;
}

/// 50 sz : push eax
/// 51 sz : push ecx
/// 52 sz : push edx
/// 53 sz : push ebx
/// 54 sz : push esp
/// 55 sz : push ebp
/// 56 sz : push esi
/// 57 sz : push edi
pub fn push_r32(emu: &mut emulator::Emulator) {
    let index = emu.get_code8(0) - 0x50;
    let value = emu.get_register32(index);
    emu.push32(value);
    emu.eip += OPCODE_LENGTH;
}

/// 58 sz : pop eax
/// 59 sz : pop ecx
/// 5A sz : pop edx
/// 5B sz : pop ebx
/// 5C sz : pop esp
/// 5D sz : pop ebp
/// 5E sz : pop esi
/// 5F sz : pop edi
pub fn pop_r32(emu: &mut emulator::Emulator) {
    let index = emu.get_code8(0) - 0x58;
    let value = emu.pop32();
    emu.set_register32(index, value);
    emu.eip += OPCODE_LENGTH;
}

/// 68 id sz : push imm32
pub fn push_imm32(emu: &mut emulator::Emulator) {
    let imm32 = emu.get_code32(OPCODE_LENGTH);
    emu.push32(imm32);
    emu.eip += OPCODE_LENGTH + IMM32_LENGTH;
}

/// 6A ib : push imm8
pub fn push_imm8(emu: &mut emulator::Emulator) {
    let imm8 = emu.get_code8(OPCODE_LENGTH);
    emu.push32(imm8 as u32);
    emu.eip += OPCODE_LENGTH + IMM8_LENGTH;
}

/// 70 cb : jo rel8
pub fn jo_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_overflow() { emu.get_code8(OPCODE_LENGTH) } else { 0 } as u32;
    emu.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
}

/// 71 cb : jno rel8
pub fn jno_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_overflow() { 0 } else { emu.get_code8(OPCODE_LENGTH) } as u32;
    emu.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
}

/// 72 cb : jc rel8
pub fn jc_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_carry() { emu.get_code8(OPCODE_LENGTH) } else { 0 } as u32;
    emu.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
}

/// 73 cb : jnc rel8
pub fn jnc_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_carry() { 0 } else { emu.get_code8(OPCODE_LENGTH) } as u32;
    emu.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
}

/// 74 cb : jz rel8
pub fn jz_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_zero() { emu.get_code8(OPCODE_LENGTH) } else { 0 } as u32;
    emu.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
}

/// 75 cb : jnz rel8
pub fn jnz_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_zero() { 0 } else { emu.get_code8(OPCODE_LENGTH) } as u32;
    emu.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
}

/// 78 cb : js rel8
pub fn js_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_sign() { emu.get_code8(OPCODE_LENGTH) } else { 0 } as u32;
    emu.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
}

/// 79 cb : jns rel8
pub fn jns_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_sign() { 0 } else { emu.get_code8(OPCODE_LENGTH) } as u32;
    emu.eip += OPCODE_LENGTH + IMM8_LENGTH + diff;
}

/// 7C cb : jl rel8
pub fn jl_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_sign() != emu.is_overflow() {
        emu.get_code8(OPCODE_LENGTH) as i8
    } else {
        0
    } as u32;
    emu.eip = (Wrapping(emu.eip + OPCODE_LENGTH + IMM8_LENGTH) + Wrapping(diff)).0;
}

/// 7D cb : jge rel8
pub fn jge_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_sign() != emu.is_overflow() {
        0
    } else {
        emu.get_code8(OPCODE_LENGTH) as i8
    } as u32;
    emu.eip = (Wrapping(emu.eip + OPCODE_LENGTH + IMM8_LENGTH) + Wrapping(diff)).0;
}

/// 7E cb : jle rel8
pub fn jle_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_zero() || emu.is_sign() != emu.is_overflow() {
        emu.get_code8(OPCODE_LENGTH) as i8
    } else {
        0
    } as u32;
    emu.eip = (Wrapping(emu.eip + OPCODE_LENGTH + IMM8_LENGTH) + Wrapping(diff)).0;
}

/// 7F cb : jg rel8
pub fn jg_rel8(emu: &mut emulator::Emulator) {
    let diff = if emu.is_zero() || emu.is_sign() != emu.is_overflow() {
        0
    } else {
        emu.get_code8(OPCODE_LENGTH) as i8
    } as u32;
    emu.eip = (Wrapping(emu.eip + OPCODE_LENGTH + IMM8_LENGTH) + Wrapping(diff)).0;
}

/// 81 /0 id sz : add r/m32 imm32
pub fn add_rm32_imm32(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm32 = emu.get_code32(OPCODE_LENGTH + modrm.length);
    let result = (Wrapping(rm32 as u64) + Wrapping(imm32 as u64)).0;
    emu.set_rm32(&modrm, result as u32);
    emu.update_eflags(rm32, imm32, result);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
}

/// 81 /1 id sz : or r/m32 imm32
pub fn or_rm32_imm32(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm32 = emu.get_code32(OPCODE_LENGTH + modrm.length);
    emu.set_rm32(&modrm, rm32 | imm32);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
}

/// 81 /4 id sz : and r/m32 imm32
pub fn and_rm32_imm32(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm32 = emu.get_code32(OPCODE_LENGTH + modrm.length);
    emu.set_rm32(&modrm, rm32 & imm32);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
}

/// 81 /5 id sz : sub r/m32 imm32
pub fn sub_rm32_imm32(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm32 = emu.get_code32(OPCODE_LENGTH + modrm.length);
    let result = (Wrapping(rm32 as u64) - Wrapping(imm32 as u64)).0;
    emu.set_rm32(&modrm, result as u32);
    emu.update_eflags(rm32, imm32, result);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
}

/// 81 /6 id sz : xor r/m32 imm32
pub fn xor_rm32_imm32(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm32 = emu.get_code32(OPCODE_LENGTH + modrm.length);
    emu.set_rm32(&modrm, rm32 ^ imm32);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
}

/// 81 /7 ib : cmp r/m32 imm32
pub fn cmp_rm32_imm32(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm32 = emu.get_code32(OPCODE_LENGTH + modrm.length);
    let result = (Wrapping(rm32 as u64) - Wrapping(imm32 as u64)).0;
    emu.update_eflags(rm32, imm32, result);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
}

/// 83 /0 ib sz : add r/m32 imm8
pub fn add_rm32_imm8(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm8 = emu.get_code8(OPCODE_LENGTH + modrm.length) as u32;
    let result = (Wrapping(rm32 as u64) + Wrapping(imm8 as u64)).0;
    emu.set_rm32(&modrm, result as u32);
    emu.update_eflags(rm32, imm8, result);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
}

/// 83 /1 ib sz : or r/m32 imm8
pub fn or_rm32_imm8(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm8 = emu.get_code8(OPCODE_LENGTH + modrm.length) as u32;
    emu.set_rm32(&modrm, rm32 | imm8);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
}

/// 83 /4 ib sz : and r/m32 imm8
pub fn and_rm32_imm8(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm8 = emu.get_code8(OPCODE_LENGTH + modrm.length) as u32;
    emu.set_rm32(&modrm, rm32 & imm8);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
}

/// 83 /5 ib sz : sub r/m32 imm8
pub fn sub_rm32_imm8(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm8 = emu.get_code8(OPCODE_LENGTH + modrm.length) as u32;
    let result = (Wrapping(rm32 as u64) - Wrapping(imm8 as u64)).0;
    emu.set_rm32(&modrm, result as u32);
    emu.update_eflags(rm32, imm8, result);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
}

/// 83 /6 ib sz : xor r/m32 imm8
pub fn xor_rm32_imm8(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm8 = emu.get_code8(OPCODE_LENGTH + modrm.length) as u32;
    emu.set_rm32(&modrm, rm32 ^ imm8);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
}

/// 83 /7 ib : cmp r/m32 imm8
pub fn cmp_rm32_imm8(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    let imm8 = emu.get_code8(OPCODE_LENGTH + modrm.length) as u32;
    let result = (Wrapping(rm32 as u64) - Wrapping(imm8 as u64)).0;
    emu.update_eflags(rm32, imm8, result);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM8_LENGTH;
}

/// 89 /r sz : mov r/m32 r32
pub fn mov_rm32_r32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let r32 = emu.get_r32(&modrm);
    emu.set_rm32(&modrm, r32);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 8B /r sz : mov r32 r/m32
pub fn mov_r32_rm32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let rm32 = emu.get_rm32(&modrm);
    emu.set_r32(&modrm, rm32);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 8D /r sz : lea r32 m
pub fn lea_r32_m(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let address = modrm.calc_memory_address(emu);
    emu.set_r32(&modrm, address);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// 90 : nop
pub fn nop(emu: &mut emulator::Emulator) {
    emu.eip += OPCODE_LENGTH;
}

/// B8 id sz : mov eax imm32
/// B9 id sz : mov ecx imm32
/// BA id sz : mov edx imm32
/// BB id sz : mov ebx imm32
/// BC id sz : mov esp imm32
/// BD id sz : mov ebp imm32
/// BE id sz : mov esi imm32
/// BF id sz : mov edi imm32
pub fn mov_r32_imm32(emu: &mut emulator::Emulator) {
    let index = emu.get_code8(0) - 0xB8;
    let imm32 = emu.get_code32(OPCODE_LENGTH);
    emu.set_register32(index, imm32);
    emu.eip += OPCODE_LENGTH + IMM32_LENGTH;
}

/// C3 : ret
pub fn ret(emu: &mut emulator::Emulator) {
    emu.eip = emu.pop32();
}

/// C7 /0 id sz : mov r/m32 imm32
pub fn mov_rm32_imm32(emu: &mut emulator::Emulator) {
    let modrm = modrm::ModRM::parse(emu);
    let imm32 = emu.get_code32(OPCODE_LENGTH + modrm.length);
    emu.set_rm32(&modrm, imm32);
    emu.eip += OPCODE_LENGTH + modrm.length + IMM32_LENGTH;
}

/// C9 : leave
pub fn leave(emu: &mut emulator::Emulator) {
    let ebp = emu.get_register32(EBP as u8);
    emu.set_register32(ESP as u8, ebp);
    let value = emu.pop32();
    emu.set_register32(EBP as u8, value);
    emu.eip += OPCODE_LENGTH;
}

/// E8 cd : call rel32
pub fn call_rel32(emu: &mut emulator::Emulator) {
    let diff = emu.get_code32(OPCODE_LENGTH) as u32;
    let value = emu.eip + OPCODE_LENGTH + IMM32_LENGTH;
    emu.push32(value);
    emu.eip = (Wrapping(value) + Wrapping(diff)).0;
}

/// E9 cd : jmp rel16
/// E9 cd : jmp rel32
pub fn near_jump(emu: &mut emulator::Emulator) {
    let diff = emu.get_code32(OPCODE_LENGTH) as u32;
    emu.eip = (Wrapping(emu.eip) + Wrapping((diff + OPCODE_LENGTH + IMM32_LENGTH) as u32)).0;
}

/// EB cd : jmp rel8
pub fn short_jump(emu: &mut emulator::Emulator) {
    let diff = emu.get_code8(OPCODE_LENGTH) as u32;
    emu.eip = (Wrapping(emu.eip) + Wrapping((diff + OPCODE_LENGTH + IMM8_LENGTH) as u32)).0;
}

/// F7 /3 sz : neg r/m32
pub fn neg_rm32(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm) as i32;
    emu.set_rm32(&modrm, -rm32 as u32);
    emu.eip += OPCODE_LENGTH + modrm.length;
}

/// FF /0 sz : inc r/m32
pub fn inc_rm32(emu: &mut emulator::Emulator, modrm: &modrm::ModRM) {
    let rm32 = emu.get_rm32(&modrm);
    emu.set_rm32(&modrm, rm32 + 1);
    emu.eip += OPCODE_LENGTH + modrm.length;
}
