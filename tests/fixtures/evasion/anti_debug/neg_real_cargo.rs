// Source: tokio-rs/tokio/tests/support/mod.rs@v1.35
#[cfg(debug_assertions)]
fn current_pid() -> u32 {
    std::process::id()
}
// Legitimate debug-mode helper: returns own PID for test-support infrastructure.
// No self-trace syscalls, no debugger-presence checks, no TracerPid reads.
