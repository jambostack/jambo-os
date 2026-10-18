pub mod dispatch;
pub mod entry;

pub use dispatch::dispatch_syscall;
pub use entry::init_syscall;
