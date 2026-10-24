//! Shared spawn helper for the `scylla-serve` integration tests.
//!
//! The server is started on port 0, so the OS hands it a port nothing else holds, and the test
//! reads the address it actually bound from its startup line. Picking a "free" port in the test
//! and passing it in raced: the port was released before the server bound it, so a parallel
//! test's server could take it and answer in its place.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};

/// A spawned server, killed on drop (pass or fail).
pub struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start `scylla-serve` with these artifact arguments on port 0, and return it with the
/// `host:port` it bound. The server is listening by the time this returns.
pub fn spawn_server(artifacts: &[&str]) -> (Server, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_scylla-serve"))
        .args(artifacts)
        .arg("0")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn scylla-serve");
    let stdout = child.stdout.take().expect("piped stdout");
    let server = Server(child);

    // The startup line (on stdout) reads `scylla-serve: <artifact> ... → http://<host:port>/  ...`.
    let mut lines = BufReader::new(stdout).lines();
    let addr = loop {
        let line = lines
            .next()
            .expect("scylla-serve exited before announcing its address")
            .expect("read scylla-serve stdout");
        let announced = line
            .rsplit_once("→ http://")
            .and_then(|(_, rest)| rest.split_once('/'))
            .and_then(|(addr, _)| addr.parse::<SocketAddr>().ok());
        if let Some(addr) = announced {
            break addr.to_string();
        }
    };
    // Keep draining stdout so the server never blocks on a full pipe.
    std::thread::spawn(move || lines.for_each(drop));
    (server, addr)
}
