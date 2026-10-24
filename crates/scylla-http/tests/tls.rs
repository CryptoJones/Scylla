//! TLS for the HTTP/JSON gateway (DD-035): a self-signed cert (rcgen) → HTTPS server. A plaintext
//! request to the HTTPS port gets no data; an HTTPS request (curl, where available) does.

mod common;

use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, Instant};

fn have_curl() -> bool {
    Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn http_gateway_serves_over_tls() {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).expect("gen cert");
    let pid = std::process::id();
    let dir = std::env::temp_dir();
    let cert_path = dir.join(format!("scylla-http-tls-{pid}.crt"));
    let key_path = dir.join(format!("scylla-http-tls-{pid}.key"));
    std::fs::write(&cert_path, ck.cert.pem()).unwrap();
    std::fs::write(&key_path, ck.key_pair.serialize_pem()).unwrap();

    let (_srv, addr) = common::spawn_gateway(&[
        ("SCYLLA_HTTP_TLS_CERT", cert_path.as_os_str()),
        ("SCYLLA_HTTP_TLS_KEY", key_path.as_os_str()),
    ]);
    let port = addr.rsplit_once(':').expect("host:port").1.to_string();

    // Wait for the port to be listening.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(&addr).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "TLS gateway never came up");
        std::thread::sleep(Duration::from_millis(50));
    }
    // Give the TLS listener a moment to be fully ready.
    std::thread::sleep(Duration::from_millis(200));

    // A PLAINTEXT request to the HTTPS port must not return data (the TLS handshake rejects it).
    let plain = ureq::get(&format!("http://{addr}/api/info")).call();
    let leaked = plain
        .ok()
        .and_then(|r| r.into_string().ok())
        .map(|b| b.contains("functions"))
        .unwrap_or(false);
    assert!(
        !leaked,
        "a plaintext request must not get data from the TLS server"
    );

    // An HTTPS request (curl, trusting the self-signed cert) gets the JSON. Skipped if curl is absent.
    if have_curl() {
        let out = Command::new("curl")
            .args([
                "-s",
                "--cacert",
                cert_path.to_str().unwrap(),
                &format!("https://localhost:{port}/api/info"),
            ])
            .output()
            .expect("run curl");
        let body = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "curl over TLS should succeed (stderr aside)"
        );
        assert!(
            body.contains("\"functions\":13"),
            "TLS info via curl: {body}"
        );
    }

    let _ = std::fs::remove_file(&cert_path);
    let _ = std::fs::remove_file(&key_path);
}
