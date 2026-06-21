#![no_main]
//! DD-039 PRIMARY target — the `.scylla` loader must be total on arbitrary bytes.
//! This is what turns DD-036's "never panics / never OOMs" from a hope into a proven claim.
//! The loader target gates v1.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Property: Ok or a typed LoadError, never a panic/abort.
    let _ = scylla_schema::load(data);
});
