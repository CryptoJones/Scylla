//! M2 — the one-way OBSERVATION CHANNEL's host-side reader.
//!
//! The containment tier (M1) runs the sample with NO egress and NO host FS, so a recorded trace
//! leaves the guest over exactly ONE bounded channel: the guest writes a framed trace to its serial
//! console (`ttyS0`), and the host reads that captured serial stream. The channel is strictly
//! guest→host — the guest cannot use it to reach the host.
//!
//! The host then treats the stream EXACTLY like a stranger's `.scylla` (the DD-036 total-loader
//! discipline): **bound every dimension first, validate, then quarantine on any violation — never
//! `eval`, never trust because "we observed it."** A sample that detects the harness and emits an
//! adversarial / oversized / malformed trace (GAP-6) must, at worst, get its trace REJECTED — it must
//! never panic, hang, or OOM this reader, and never reach the host. That property is the M2 gate, and
//! the `gap6` fuzz at the bottom is its proof.
//!
//! Wire frame (amid arbitrary console noise, which is ignored):
//! ```text
//! SCYLLA-TRACE-V1 BEGIN
//! <base64 of the JSON trace, across one or more lines>
//! SCYLLA-TRACE-V1 END len=<decoded-bytes> fnv=<fnv1a64-hex>
//! ```
//! The JSON trace is `{"edges":[{"from":"..","to":"..","confidence":0..=100}, ...]}` — the same
//! `ObservedEdge`s the `DynamicHarness` trait yields, so M3/M4 drop in behind it unchanged.

use std::io::Read;

use crate::harness::ObservedEdge;
use serde_json::Value;

// --- caps: bound EVERY dimension before trusting anything (DD-036) ---
pub const MAX_CHANNEL_BYTES: usize = 1 << 20; // 1 MiB hard cap on the raw channel slurp
pub const MAX_LINES: usize = 20_000;
pub const MAX_LINE_LEN: usize = 16 * 1024;
pub const MAX_DECODED_BYTES: usize = 256 * 1024;
pub const MAX_RECORDS: usize = 4096;
pub const MAX_NAME_LEN: usize = 512;

const BEGIN: &[u8] = b"SCYLLA-TRACE-V1 BEGIN";
const END_PREFIX: &[u8] = b"SCYLLA-TRACE-V1 END";

/// Every way the channel can be rejected — a CLOSED set, all bounded, none of them a panic/hang/OOM.
#[derive(Debug, PartialEq, Eq)]
pub enum ChannelReject {
    TooLarge,
    TooManyLines,
    LineTooLong,
    NoFrame,
    BadBase64,
    DecodedTooLarge,
    LenMismatch,
    ChecksumMismatch,
    BadJson,
    NotAnArray,
    TooManyRecords,
    BadField(&'static str),
}

impl std::fmt::Display for ChannelReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ChannelReject::*;
        match self {
            TooLarge => write!(f, "raw channel exceeded {MAX_CHANNEL_BYTES} bytes"),
            TooManyLines => write!(f, "exceeded {MAX_LINES} lines"),
            LineTooLong => write!(f, "a line exceeded {MAX_LINE_LEN} bytes"),
            NoFrame => write!(f, "no well-formed SCYLLA-TRACE-V1 BEGIN/END frame"),
            BadBase64 => write!(f, "frame body is not valid base64"),
            DecodedTooLarge => write!(f, "decoded trace exceeded {MAX_DECODED_BYTES} bytes"),
            LenMismatch => write!(f, "declared len != decoded len"),
            ChecksumMismatch => write!(f, "declared fnv != decoded fnv (corruption/forgery)"),
            BadJson => write!(f, "decoded trace is not valid JSON (or too deeply nested)"),
            NotAnArray => write!(f, "trace has no `edges` array"),
            TooManyRecords => write!(f, "edges exceeded {MAX_RECORDS} records"),
            BadField(w) => write!(f, "edge field invalid: {w}"),
        }
    }
}

/// Read a recorded trace off the channel. Returns the validated edges, or a bounded rejection.
/// Memory is bounded to ~`MAX_CHANNEL_BYTES` regardless of input shape (the `take` slurp cap), so a
/// no-newline gigabyte or a fork of lines cannot exhaust the host.
pub fn read_trace<R: Read>(src: R) -> Result<Vec<ObservedEdge>, ChannelReject> {
    // 1. Bounded slurp — read at most cap+1 bytes, ever. Overflow => reject (don't keep reading).
    let mut buf = Vec::new();
    src.take((MAX_CHANNEL_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|_| ChannelReject::NoFrame)?;
    if buf.len() > MAX_CHANNEL_BYTES {
        return Err(ChannelReject::TooLarge);
    }

    // 2. Split into capped lines.
    let mut lines: Vec<&[u8]> = Vec::new();
    for line in buf.split(|&b| b == b'\n') {
        if lines.len() >= MAX_LINES {
            return Err(ChannelReject::TooManyLines);
        }
        if line.len() > MAX_LINE_LEN {
            return Err(ChannelReject::LineTooLong);
        }
        lines.push(line);
    }

    // 3. Locate the frame, ignoring all surrounding console noise (kernel boot spam, etc.).
    let begin = lines
        .iter()
        .position(|l| trim(l) == BEGIN)
        .ok_or(ChannelReject::NoFrame)?;
    let end_rel = lines[begin + 1..]
        .iter()
        .position(|l| starts_with(trim(l), END_PREFIX))
        .ok_or(ChannelReject::NoFrame)?;
    let end = begin + 1 + end_rel;

    // 4. Concatenate the base64 body, guarding the ENCODED size (so we never decode the unbounded).
    let mut b64: Vec<u8> = Vec::new();
    for l in &lines[begin + 1..end] {
        b64.extend_from_slice(trim(l));
        if b64.len() > MAX_DECODED_BYTES / 3 * 4 + 8 {
            return Err(ChannelReject::DecodedTooLarge);
        }
    }

    // 5. Parse the END line's declared length + checksum.
    let (declared_len, declared_fnv) = parse_end(trim(lines[end]))?;

    // 6. Decode (std-only) and re-check the DECODED size.
    let decoded = b64_decode(&b64).map_err(|_| ChannelReject::BadBase64)?;
    if decoded.len() > MAX_DECODED_BYTES {
        return Err(ChannelReject::DecodedTooLarge);
    }

    // 7. Framing/corruption integrity (the content is STILL untrusted after this passes).
    if decoded.len() != declared_len {
        return Err(ChannelReject::LenMismatch);
    }
    if fnv1a64(&decoded) != declared_fnv {
        return Err(ChannelReject::ChecksumMismatch);
    }

    // 8. Validate-then-quarantine the JSON against a STRICT schema. serde_json's own recursion limit
    //    bounds nesting (a billion-laughs payload errors out, it does not blow the stack).
    let v: Value = serde_json::from_slice(&decoded).map_err(|_| ChannelReject::BadJson)?;
    let arr = v
        .get("edges")
        .and_then(Value::as_array)
        .ok_or(ChannelReject::NotAnArray)?;
    if arr.len() > MAX_RECORDS {
        return Err(ChannelReject::TooManyRecords);
    }
    let mut out = Vec::with_capacity(arr.len());
    for rec in arr {
        let from = rec.get("from").and_then(Value::as_str).ok_or(ChannelReject::BadField("from"))?;
        let to = rec.get("to").and_then(Value::as_str).ok_or(ChannelReject::BadField("to"))?;
        let conf = rec
            .get("confidence")
            .and_then(Value::as_u64)
            .ok_or(ChannelReject::BadField("confidence"))?;
        if from.is_empty() || to.is_empty() || from.len() > MAX_NAME_LEN || to.len() > MAX_NAME_LEN {
            return Err(ChannelReject::BadField("name-length"));
        }
        if conf > 100 {
            return Err(ChannelReject::BadField("confidence-range"));
        }
        out.push(ObservedEdge { from: from.to_string(), to: to.to_string(), confidence: conf as u8 });
    }
    Ok(out)
}

/// DD-035: any onward DISPLAY of the attacker-influenced names is sanitized (control/escape bytes
/// stripped) so a crafted name can't forge log structure or inject a terminal escape.
pub fn sanitize_inline(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '.' } else { c }).collect()
}

/// Build a valid frame for a JSON body (used by the `m2-make` demo subcommand and the fuzz tests).
pub fn make_frame(json: &str) -> String {
    let body = json.as_bytes();
    let b64 = b64_encode(body); // ASCII, so byte-slicing on 4 KiB boundaries is UTF-8-safe
    let wrapped: Vec<&str> = (0..b64.len().max(1))
        .step_by(4096)
        .map(|i| &b64[i..(i + 4096).min(b64.len())])
        .collect();
    format!(
        "SCYLLA-TRACE-V1 BEGIN\n{}\nSCYLLA-TRACE-V1 END len={} fnv={:016x}\n",
        wrapped.join("\n"),
        body.len(),
        fnv1a64(body)
    )
}

/// `m2-read`: read the channel off stdin, print accepted edges (DD-035-sanitized) or quarantine.
pub fn run_stdin() -> ! {
    match read_trace(std::io::stdin().lock()) {
        Ok(edges) => {
            println!("[m2] ACCEPTED {} observed edge(s) — bounded + validated, never eval'd:", edges.len());
            for e in &edges {
                println!(
                    "[m2]   {} -> {}  (conf {})",
                    sanitize_inline(&e.from),
                    sanitize_inline(&e.to),
                    e.confidence
                );
            }
            std::process::exit(0);
        }
        Err(r) => {
            eprintln!("[m2] QUARANTINED — channel input rejected: {r}");
            std::process::exit(2);
        }
    }
}

// --- std-only helpers (no extra dependency, so the isolated spike crate builds offline) ---

fn trim(l: &[u8]) -> &[u8] {
    let (mut s, mut e) = (0, l.len());
    while s < e && matches!(l[s], b' ' | b'\t' | b'\r') {
        s += 1;
    }
    while e > s && matches!(l[e - 1], b' ' | b'\t' | b'\r') {
        e -= 1;
    }
    &l[s..e]
}

fn starts_with(h: &[u8], n: &[u8]) -> bool {
    h.len() >= n.len() && &h[..n.len()] == n
}

fn parse_end(line: &[u8]) -> Result<(usize, u64), ChannelReject> {
    let s = std::str::from_utf8(line).map_err(|_| ChannelReject::NoFrame)?;
    let (mut len, mut fnv) = (None, None);
    for tok in s.split_whitespace() {
        if let Some(n) = tok.strip_prefix("len=") {
            len = n.parse::<usize>().ok();
        } else if let Some(h) = tok.strip_prefix("fnv=") {
            fnv = u64::from_str_radix(h, 16).ok();
        }
    }
    match (len, fnv) {
        (Some(l), Some(f)) => Ok((l, f)),
        _ => Err(ChannelReject::NoFrame),
    }
}

fn fnv1a64(data: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        s.push(T[(n >> 18 & 63) as usize] as char);
        s.push(T[(n >> 12 & 63) as usize] as char);
        s.push(if chunk.len() > 1 { T[(n >> 6 & 63) as usize] as char } else { '=' });
        s.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    s
}

fn b64_decode(input: &[u8]) -> Result<Vec<u8>, ()> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3 + 3);
    let (mut acc, mut nbits) = (0u32, 0u32);
    for &c in input {
        if matches!(c, b'=' | b'\r' | b'\n' | b' ' | b'\t') {
            continue;
        }
        let v = val(c).ok_or(())? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Ok(out)
}

// ============================================================================================
// GAP-6 fuzz — the M2 gate. Every adversarial input must RETURN a bounded rejection (the test
// returning at all proves no panic / hang / OOM), and a valid trace must round-trip.
// ============================================================================================
#[cfg(test)]
mod gap6 {
    use super::*;

    fn good_body() -> String {
        r#"{"edges":[{"from":"main","to":"gcd","confidence":90},{"from":"gcd","to":"mod","confidence":75}]}"#.to_string()
    }

    #[test]
    fn valid_trace_round_trips() {
        let frame = make_frame(&good_body());
        let edges = read_trace(frame.as_bytes()).expect("valid frame accepted");
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0].from, "main");
        assert_eq!(edges[0].confidence, 90);
    }

    #[test]
    fn ignores_surrounding_console_noise() {
        // The real serial stream is the kernel's boot spam with the frame buried in it.
        let frame = make_frame(&good_body());
        let noisy = format!(
            "[    0.000000] Linux version 7.0.0\n[    0.12] booting\nrandom junk !!!\n{frame}[    9.99] reboot: Power down\n"
        );
        assert_eq!(read_trace(noisy.as_bytes()).unwrap().len(), 2);
    }

    #[test]
    fn oversized_raw_is_bounded_and_rejected() {
        let huge = vec![b'A'; MAX_CHANNEL_BYTES + 4096];
        assert_eq!(read_trace(&huge[..]), Err(ChannelReject::TooLarge));
    }

    #[test]
    fn single_giant_line_no_newline_is_bounded() {
        let huge = vec![b'X'; 4 * 1024 * 1024]; // 4 MiB, no '\n'
        assert_eq!(read_trace(&huge[..]), Err(ChannelReject::TooLarge));
    }

    #[test]
    fn too_many_lines() {
        let many = vec![b'\n'; MAX_LINES + 10];
        assert_eq!(read_trace(&many[..]), Err(ChannelReject::TooManyLines));
    }

    #[test]
    fn line_too_long() {
        let mut v = b"SCYLLA-TRACE-V1 BEGIN\n".to_vec();
        v.extend(vec![b'A'; MAX_LINE_LEN + 1]);
        v.push(b'\n');
        assert_eq!(read_trace(&v[..]), Err(ChannelReject::LineTooLong));
    }

    #[test]
    fn no_frame() {
        assert_eq!(read_trace(&b"nothing to see here\n"[..]), Err(ChannelReject::NoFrame));
    }

    #[test]
    fn begin_without_end() {
        assert_eq!(read_trace(&b"SCYLLA-TRACE-V1 BEGIN\nabc\n"[..]), Err(ChannelReject::NoFrame));
    }

    #[test]
    fn bad_base64() {
        let frame = "SCYLLA-TRACE-V1 BEGIN\n@@@not base64@@@\nSCYLLA-TRACE-V1 END len=5 fnv=0\n";
        assert_eq!(read_trace(frame.as_bytes()), Err(ChannelReject::BadBase64));
    }

    #[test]
    fn len_mismatch() {
        let body = good_body();
        let mut frame = make_frame(&body);
        frame = frame.replace(&format!("len={}", body.len()), "len=999999");
        assert_eq!(read_trace(frame.as_bytes()), Err(ChannelReject::LenMismatch));
    }

    #[test]
    fn checksum_mismatch() {
        let body = good_body();
        let correct = format!("fnv={:016x}", fnv1a64(body.as_bytes()));
        let forged = make_frame(&body).replace(&correct, "fnv=0000000000000000");
        assert_eq!(read_trace(forged.as_bytes()), Err(ChannelReject::ChecksumMismatch));
    }

    #[test]
    fn decoded_but_invalid_json() {
        let frame = make_frame("this is not json {{{");
        assert_eq!(read_trace(frame.as_bytes()), Err(ChannelReject::BadJson));
    }

    #[test]
    fn deeply_nested_json_does_not_blow_the_stack() {
        // billion-laughs-ish: 5000 nested arrays, well under the size cap — serde_json's recursion
        // limit must turn this into a bounded BadJson, never a stack overflow.
        let mut s = String::from("{\"edges\":");
        s.push_str(&"[".repeat(5000));
        s.push_str(&"]".repeat(5000));
        s.push('}');
        assert_eq!(read_trace(make_frame(&s).as_bytes()), Err(ChannelReject::BadJson));
    }

    #[test]
    fn no_edges_array() {
        assert_eq!(read_trace(make_frame(r#"{"nope":1}"#).as_bytes()), Err(ChannelReject::NotAnArray));
    }

    #[test]
    fn too_many_records() {
        let mut s = String::from(r#"{"edges":["#);
        for i in 0..(MAX_RECORDS + 1) {
            if i > 0 {
                s.push(',');
            }
            s.push_str(r#"{"from":"a","to":"b","confidence":1}"#);
        }
        s.push_str("]}");
        assert_eq!(read_trace(make_frame(&s).as_bytes()), Err(ChannelReject::TooManyRecords));
    }

    #[test]
    fn confidence_out_of_range() {
        let frame = make_frame(r#"{"edges":[{"from":"a","to":"b","confidence":255}]}"#);
        assert_eq!(read_trace(frame.as_bytes()), Err(ChannelReject::BadField("confidence-range")));
    }

    #[test]
    fn missing_field() {
        let frame = make_frame(r#"{"edges":[{"from":"a","confidence":1}]}"#);
        assert_eq!(read_trace(frame.as_bytes()), Err(ChannelReject::BadField("to")));
    }

    #[test]
    fn oversized_name() {
        let big = "x".repeat(MAX_NAME_LEN + 1);
        let frame = make_frame(&format!(r#"{{"edges":[{{"from":"{big}","to":"b","confidence":1}}]}}"#));
        assert_eq!(read_trace(frame.as_bytes()), Err(ChannelReject::BadField("name-length")));
    }

    #[test]
    fn control_chars_in_name_are_accepted_then_sanitized_on_display() {
        // A crafted name with an escaped ANSI ESC is a valid JSON string field (accepted as data),
        let body = r#"{"edges":[{"from":"a\u001b[31mevil","to":"b","confidence":1}]}"#;
        let edges = read_trace(make_frame(body).as_bytes()).expect("accepted as data");
        assert!(edges[0].from.chars().any(|c| c.is_control()));
        assert!(!sanitize_inline(&edges[0].from).chars().any(|c| c.is_control()));
    }
}
