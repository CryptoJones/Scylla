//! The TUI head's library half (DD-017): the `App` — the resident session plus the interaction
//! state (selection, mode, search filter) — and the `ui` renderer. The `App` carries ZERO terminal
//! or `ratatui` dependency: it is a pure projection of `scylla_port::Session`, so the conformance
//! tests drive it directly (no pty, no spawned process) and assert it reproduces the port verb for
//! verb. The binary (`main.rs`) is the thin crossterm shell that turns keystrokes into `App` calls
//! and paints the `App` with `ui::draw`.

pub mod app;
pub mod ui;
