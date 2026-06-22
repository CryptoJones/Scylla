//! WASM head (DD-028): the client port (`scylla_port`) compiled to WebAssembly so a browser
//! navigates a `.scylla` model-artifact **entirely client-side** — no server, no engine. It is
//! a new head in the hexagon's sense (the first OUT-OF-PROCESS consumer of the port): the
//! browser loads the self-contained artifact (DD-026) into a WASM `Session` and drives the same
//! navigate/zoom surface the in-process and MCP heads use.
//!
//! **Raw wasm32 C-ABI — no wasm-bindgen.** The browser instantiates the module and marshals over
//! linear memory: `scylla_alloc` for the artifact bytes in, and string results returned as a
//! `(ptr<<32 | len)` u64 the JS unpacks and then `scylla_free`s. Single loaded session, single
//! thread (a `thread_local`), read-only for v1 — a viewer over a persisted artifact. Annotation/
//! merge (which the in-core port supports) and engine verbs (decompile) are future work.

use std::cell::RefCell;

use scylla_model::StableId;
use scylla_port::{FunctionView, Session, Zoom};
use serde_json::json;

thread_local! {
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

fn zoom_of(level: u32) -> Zoom {
    match level {
        0 => Zoom::Intent,
        2 => Zoom::Detail,
        _ => Zoom::Domain,
    }
}

fn view_json(v: &FunctionView) -> serde_json::Value {
    json!({
        "id": v.id.0,
        "name": v.name,
        "summary": v.summary,
        "addr": v.addr,
        "bbCount": v.bb_count,
        "callees": v.callees,
        "callers": v.callers,
        "size": v.size,
    })
}

/// Hand a UTF-8 string to JS: leak it and pack `(ptr << 32) | len` into a u64. JS reads the bytes
/// from linear memory and then calls [`scylla_free`]. The buffer is an exact-size `Box<[u8]>`
/// (capacity == len) so the `(ptr, len)` free reconstructs the right allocation layout.
fn ret_string(s: String) -> u64 {
    let boxed: Box<[u8]> = s.into_bytes().into_boxed_slice();
    let len = boxed.len() as u64;
    let ptr = Box::into_raw(boxed) as *mut u8 as u64;
    (ptr << 32) | len
}

fn with_session(empty: &str, f: impl FnOnce(&Session) -> String) -> u64 {
    SESSION.with_borrow(|opt| match opt {
        Some(s) => ret_string(f(s)),
        None => ret_string(empty.to_string()),
    })
}

/// Allocate `len` bytes in linear memory; JS writes the artifact there, then calls [`scylla_load`].
/// Exact-size (capacity == len) so [`scylla_free`]'s `(ptr, len)` reclaim matches the layout.
#[no_mangle]
pub extern "C" fn scylla_alloc(len: usize) -> *mut u8 {
    let boxed: Box<[u8]> = vec![0u8; len].into_boxed_slice();
    Box::into_raw(boxed) as *mut u8
}

/// Free a `(ptr, len)` buffer previously handed to JS (an alloc or a returned string).
///
/// # Safety
/// `ptr`/`len` must be a buffer this module returned and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn scylla_free(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, len, len));
}

/// Load a `.scylla` model-artifact from `(ptr, len)` (the validating loader, DD-036). Returns 0
/// on success, -1 on failure.
///
/// # Safety
/// `ptr`/`len` must describe a valid byte buffer in linear memory.
#[no_mangle]
pub unsafe extern "C" fn scylla_load(ptr: *const u8, len: usize) -> i32 {
    let bytes = std::slice::from_raw_parts(ptr, len);
    match Session::from_artifact(bytes) {
        Ok(s) => {
            SESSION.with_borrow_mut(|slot| *slot = Some(s));
            0
        }
        Err(_) => -1,
    }
}

/// Artifact metadata `{name, language, functions}` as a JSON string handle.
#[no_mangle]
pub extern "C" fn scylla_info() -> u64 {
    with_session("null", |s| {
        let p = s.program();
        json!({ "name": p.name, "language": p.language, "functions": p.functions.len() })
            .to_string()
    })
}

/// All functions at a zoom altitude (0=intent, 1=domain, 2=detail) as a JSON-array handle.
#[no_mangle]
pub extern "C" fn scylla_functions(zoom: u32) -> u64 {
    with_session("[]", |s| {
        let arr: Vec<serde_json::Value> =
            s.functions(zoom_of(zoom)).iter().map(view_json).collect();
        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
    })
}

/// One function by stable id at a zoom altitude, as a JSON handle (`{error}` if the id is unknown).
#[no_mangle]
pub extern "C" fn scylla_view(id: u64, zoom: u32) -> u64 {
    with_session("null", |s| match s.view(StableId(id), zoom_of(zoom)) {
        Ok(v) => view_json(&v).to_string(),
        Err(e) => json!({ "error": e.to_string() }).to_string(),
    })
}

/// Stable ids of the functions that call `id` (call-graph navigation) as a JSON-array handle.
#[no_mangle]
pub extern "C" fn scylla_callers(id: u64) -> u64 {
    with_session("[]", |s| {
        let ids: Vec<u64> = s.callers(StableId(id)).into_iter().map(|x| x.0).collect();
        serde_json::to_string(&ids).unwrap_or_else(|_| "[]".to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zoom_levels_map() {
        assert_eq!(zoom_of(0), Zoom::Intent);
        assert_eq!(zoom_of(1), Zoom::Domain);
        assert_eq!(zoom_of(2), Zoom::Detail);
        assert_eq!(zoom_of(99), Zoom::Domain); // default altitude
    }

    // The (ptr<<32 | len) string-handle protocol is wasm32-specific (32-bit pointers); it is
    // exercised end-to-end by the headless Node verification (web/verify.mjs), not a native test.
}
