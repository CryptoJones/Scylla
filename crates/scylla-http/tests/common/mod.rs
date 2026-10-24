//! Shared spawn helper for the `scylla-http` integration tests.
//!
//! The gateway is started on `127.0.0.1:0`, so the OS hands it a port nothing else holds, and the
//! test reads the address it actually bound from its startup line. Picking a "free" port in the
//! test and passing it in raced: the port was released before the gateway bound it, so a
//! parallel test's gateway could take it and answer in its place.

use std::ffi::OsStr;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

pub const ARTIFACT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib.scylla"
);

/// Kills the gateway when the test ends, pass or fail.
pub struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `scylla-http` on `ARTIFACT` with these extra environment variables, and return it with
/// the `host:port` it bound. The gateway is listening by the time this returns.
pub fn spawn_gateway(envs: &[(&str, &OsStr)]) -> (Server, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scylla-http"))
        .args([ARTIFACT, "127.0.0.1:0"])
        .envs(envs.iter().copied())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn scylla-http");
    let stderr = child.stderr.take().expect("piped stderr");
    let server = Server(child);

    // The startup line reads `scylla-http: <artifact> on <scheme>://<host:port>/  — ...`.
    let mut lines = BufReader::new(stderr).lines();
    let addr = loop {
        let line = lines
            .next()
            .expect("scylla-http exited before announcing its address")
            .expect("read scylla-http stderr");
        let announced = line
            .split_once(" on http")
            .and_then(|(_, rest)| rest.split_once("://"))
            .and_then(|(_, rest)| rest.split_once('/'));
        if let Some((addr, _)) = announced {
            break addr.to_string();
        }
    };
    // Keep draining stderr so the gateway never blocks on a full pipe.
    std::thread::spawn(move || lines.for_each(drop));
    (server, addr)
}
