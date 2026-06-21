#![no_main]
//! DD-039 — the MCP head's input surface: hostile JSON-RPC must never panic, and dispatch
//! must always return a well-formed envelope (S2 / DD-035).
use libfuzzer_sys::fuzz_target;
use scylla_model::Program;
use scylla_port::Session;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let Ok(req) = serde_json::from_str::<serde_json::Value>(s) else { return };
    let mut session = Session::open(Program::default());
    let _ = scylla_mcp::dispatch(&mut session, &req);
});
