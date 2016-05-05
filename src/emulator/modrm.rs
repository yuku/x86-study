#[derive(Default)]
pub struct ModRM {
    pub mod_: u8,
    pub reg: u8,
    pub rm: u8,
    pub sib: u8,
    pub disp8: i8,
    pub disp32: u32,
}
