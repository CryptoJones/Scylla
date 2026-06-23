//! WASM head (DD-028): the client port (`scylla_port`) compiled to WebAssembly so a browser
//! navigates a `.scylla` model-artifact **entirely client-side** — no server, no engine. It is
//! a new head in the hexagon's sense (the first OUT-OF-PROCESS consumer of the port): the
//! browser loads the self-contained artifact (DD-026) into a WASM `Session` and drives the same
//! navigate/zoom surface the in-process and MCP heads use.
//!
//! **Raw wasm32 C-ABI — no wasm-bindgen.** The browser instantiates the module and marshals over
//! linear memory: `scylla_alloc` for the artifact bytes in, and string results returned as a
//! `(ptr<<32 | len)` u64 the JS unpacks and then `scylla_free`s. Single loaded session, single
//! thread (a `thread_local`). It navigates, annotates (rename/retype/comment), exports, merges a
//! re-analysis, and structurally diffs against another artifact — the port's full client surface,
//! client-side. Only engine verbs (decompile) remain server/JVM-only.

use std::cell::RefCell;

use scylla_model::StableId;
use scylla_port::{FunctionView, PortError, Session, Zoom};
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

/// Hand a byte buffer to JS, packed `(ptr << 32) | len` in a u64. JS reads it out of linear
/// memory then calls [`scylla_free`]. An exact-size `Box<[u8]>` (capacity == len) so the
/// `(ptr, len)` free reconstructs the right allocation layout.
fn ret_bytes(bytes: Vec<u8>) -> u64 {
    let boxed: Box<[u8]> = bytes.into_boxed_slice();
    let len = boxed.len() as u64;
    let ptr = Box::into_raw(boxed) as *mut u8 as u64;
    (ptr << 32) | len
}

fn ret_string(s: String) -> u64 {
    ret_bytes(s.into_bytes())
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

/// Apply a string-valued annotation verb to `id` from `(ptr, len)` (UTF-8). Returns 0 on success,
/// -1 on bad UTF-8 / no session / a rejected value (DD-021, e.g. a blank name).
///
/// # Safety
/// `(ptr, len)` must describe a valid byte buffer in linear memory.
unsafe fn annotate(
    id: u64,
    ptr: *const u8,
    len: usize,
    f: impl FnOnce(&mut Session, StableId, &str) -> Result<(), PortError>,
) -> i32 {
    let text = match std::str::from_utf8(std::slice::from_raw_parts(ptr, len)) {
        Ok(t) => t,
        Err(_) => return -1,
    };
    SESSION.with_borrow_mut(|opt| match opt {
        Some(s) => {
            if f(s, StableId(id), text).is_ok() {
                0
            } else {
                -1
            }
        }
        None => -1,
    })
}

/// Rename a function (durable user fact, DD-005). `(ptr, len)` = the new name. 0 ok, -1 on a blank
/// name / unknown id.
///
/// # Safety
/// `(ptr, len)` must describe a valid byte buffer in linear memory.
#[no_mangle]
pub unsafe extern "C" fn scylla_rename(id: u64, ptr: *const u8, len: usize) -> i32 {
    annotate(id, ptr, len, |s, id, t| s.rename(id, t))
}

/// Retype a function. `(ptr, len)` = the new type. 0 ok, -1 on a blank type / unknown id.
///
/// # Safety
/// `(ptr, len)` must describe a valid byte buffer in linear memory.
#[no_mangle]
pub unsafe extern "C" fn scylla_retype(id: u64, ptr: *const u8, len: usize) -> i32 {
    annotate(id, ptr, len, |s, id, t| s.retype(id, t))
}

/// Comment a function (may be empty — clearing it is a legitimate edit). 0 ok, -1 on unknown id.
///
/// # Safety
/// `(ptr, len)` must describe a valid byte buffer in linear memory.
#[no_mangle]
pub unsafe extern "C" fn scylla_comment(id: u64, ptr: *const u8, len: usize) -> i32 {
    annotate(id, ptr, len, |s, id, t| s.comment(id, t))
}

/// Serialize the (possibly annotated) session back to a `.scylla` model-artifact (DD-026), as a
/// byte handle JS reads + downloads, then frees. Annotations persist on the stable IDs — re-load
/// the exported artifact and the renames survive (git-for-RE, in the browser).
#[no_mangle]
pub extern "C" fn scylla_export() -> u64 {
    SESSION.with_borrow(|opt| match opt {
        Some(s) => ret_bytes(s.to_artifact()),
        None => ret_bytes(Vec::new()),
    })
}

/// Re-anchor the current session's user facts onto a RE-ANALYSIS (a fresh `.scylla` from `(ptr,len)`,
/// with different stable ids) by structural identity (DD-005), then make the merged model the
/// session. Returns `{merged, flagged}` — facts confidently carried, and those a structural
/// ambiguity flagged for review (fail-closed: a near-tie never anchors). The browser payoff: rename
/// a function, re-import a rebuilt binary, and the rename follows the function across the rebuild.
///
/// # Safety
/// `(ptr, len)` must describe a valid byte buffer in linear memory.
#[no_mangle]
pub unsafe extern "C" fn scylla_merge(ptr: *const u8, len: usize) -> u64 {
    let bytes = std::slice::from_raw_parts(ptr, len);
    // Pure port consumer: load the re-analysis as a Session, then drive the port's `merge_from`
    // (re-anchor + adopt) — no reaching into the merge engine / schema directly.
    let other = match Session::from_artifact(bytes) {
        Ok(s) => s,
        Err(e) => return ret_string(json!({ "error": e.to_string() }).to_string()),
    };
    SESSION.with_borrow_mut(|opt| match opt {
        Some(session) => {
            let report = session.merge_from(&other);
            ret_string(json!({ "merged": report.merged, "flagged": report.flagged }).to_string())
        }
        None => ret_string(json!({ "error": "no session loaded" }).to_string()),
    })
}

/// Structurally diff the current session against ANOTHER `.scylla` from `(ptr, len)` (DD-017 `diff`):
/// pair functions by address-independent structural identity, reporting matched pairs plus the
/// functions unique to each side, by display name. READ-ONLY — the loaded session is untouched (the
/// other artifact is only compared, never adopted; that is what [`scylla_merge`] is for). Returns
/// `{matched, changed, onlyHere, onlyThere}` — `changed` being functions whose body was modified
/// but re-identified by call-graph propagation (DD-017), each as `[here, there]` — or `{error}`. The browser
/// payoff: load build A, diff against build B, and see what the recompile changed — no server, and
/// a rename here shows through because the matcher is identity-based, not address-based.
///
/// # Safety
/// `(ptr, len)` must describe a valid byte buffer in linear memory.
#[no_mangle]
pub unsafe extern "C" fn scylla_diff(ptr: *const u8, len: usize) -> u64 {
    let bytes = std::slice::from_raw_parts(ptr, len);
    SESSION.with_borrow(|opt| {
        let Some(here) = opt.as_ref() else {
            return ret_string(json!({ "error": "no session loaded" }).to_string());
        };
        let there = match Session::from_artifact(bytes) {
            Ok(s) => s,
            Err(e) => return ret_string(json!({ "error": e.to_string() }).to_string()),
        };
        let d = here.diff(&there);
        // Match-confidence breakdown by ladder rung (DD-017): exact is certain, fuzzy a best-guess.
        let mut methods = serde_json::Map::new();
        let mut confidence = serde_json::Map::new();
        for (name, info) in &d.provenance {
            let e = methods.entry(info.method.as_str()).or_insert(json!(0));
            *e = json!(e.as_u64().unwrap_or(0) + 1);
            confidence.insert(
                name.clone(),
                json!({"method": info.method.as_str(), "confidence": info.confidence}),
            );
        }
        ret_string(
            json!({
                "matched": d.matched,
                "changed": d.changed,
                "onlyHere": d.only_here,
                "onlyThere": d.only_there,
                "methods": serde_json::Value::Object(methods),
                "confidence": serde_json::Value::Object(confidence),
            })
            .to_string(),
        )
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
