//! End-to-end TLS for the remote head (DD-035): generate a self-signed cert (rcgen), run
//! `scylla-rpc-serve` with TLS, and drive it with `scylla-rpc-connect` over TLS — so the auth token
//! and the model never cross the wire in the clear. A plaintext client is rejected.

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const ARTIFACT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../scylla-wasm/web/mathlib.scylla"
);

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server(Child);
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn remote_head_works_over_tls_and_rejects_plaintext() {
    // A throwaway self-signed cert for "localhost".
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("gen cert");
    let pid = std::process::id();
    let dir = std::env::temp_dir();
    let cert_path = dir.join(format!("scylla-rpc-tls-{pid}.crt"));
    let key_path = dir.join(format!("scylla-rpc-tls-{pid}.key"));
    std::fs::write(&cert_path, ck.cert.pem()).unwrap();
    std::fs::write(&key_path, ck.key_pair.serialize_pem()).unwrap();

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let _srv = Server(
        Command::new(env!("CARGO_BIN_EXE_scylla-rpc-serve"))
            .args([ARTIFACT, &addr])
            .env("SCYLLA_RPC_TLS_CERT", &cert_path)
            .env("SCYLLA_RPC_TLS_KEY", &key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn scylla-rpc-serve"),
    );

    // A TLS client trusts the cert (as the CA) and verifies the "localhost" name.
    let tls_connect = |args: &[&str]| -> (i32, String) {
        let mut full = vec![addr.as_str()];
        full.extend_from_slice(args);
        let out = Command::new(env!("CARGO_BIN_EXE_scylla-rpc-connect"))
            .args(&full)
            .env("SCYLLA_RPC_TLS_CA", &cert_path)
            .env("SCYLLA_RPC_TLS_SNI", "localhost")
            .env_remove("SCYLLA_RPC_TOKEN")
            .output()
            .expect("run scylla-rpc-connect");
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        )
    };

    // Wait until the TLS server is up.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if tls_connect(&["info"]).0 == 0 {
            break;
        }
        assert!(Instant::now() < deadline, "TLS server never came up");
        std::thread::sleep(Duration::from_millis(50));
    }

    // info, navigation, diff — all over the encrypted wire.
    let (code, out) = tls_connect(&["info"]);
    assert_eq!(code, 0, "TLS info exit 0");
    assert!(out.contains("functions: 13"), "TLS info: {out}");
    assert_eq!(tls_connect(&["functions"]).0, 0, "TLS functions works");

    // A PLAINTEXT client (no TLS) against the TLS server must fail, and leak nothing.
    let out = Command::new(env!("CARGO_BIN_EXE_scylla-rpc-connect"))
        .args([addr.as_str(), "info"])
        .env_remove("SCYLLA_RPC_TLS_CA")
        .env_remove("SCYLLA_RPC_TOKEN")
        .output()
        .expect("run scylla-rpc-connect");
    let plain = (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    );
    assert_ne!(
        plain.0, 0,
        "a plaintext client must fail against a TLS server"
    );
    assert!(
        !plain.1.contains("functions:"),
        "no data leaks to a plaintext client: {}",
        plain.1
    );

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
}
