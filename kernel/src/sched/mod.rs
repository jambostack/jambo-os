pub mod context;
pub mod eevdf;
pub mod interactive_test;
pub mod preempt_test;
pub mod process;
pub mod ring3_test;
pub mod thread;

pub use context::{enter_user_mode, switch_context};
pub use eevdf::{EevdfScheduler, SCHEDULER};
pub use interactive_test::execute_interactive_io_test;
pub use preempt_test::execute_preemption_test;
pub use process::{allocate_pid, Process, ProcessState};
pub use ring3_test::execute_ring3_roundtrip_test;
pub use thread::{allocate_tid, Thread, ThreadState};

#[inline]
pub fn on_timer_tick() {
    EevdfScheduler::on_timer_tick();
}
