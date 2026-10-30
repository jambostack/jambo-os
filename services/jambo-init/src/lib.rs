#![no_std]

pub const INIT_VERSION: &str = "0.3.41";

/// État du superviseur racine JamboInit
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorState {
    Booting,
    Running,
    ShuttingDown,
}
