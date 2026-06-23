// Headless verification of the WASM head: load scylla_wasm.wasm + the sample artifact, navigate,
// and assert it reproduces the model. Mirrors EXACTLY what index.html does in the browser (same
// WebAssembly API + i64/BigInt string-handle marshaling), so a PASS here means the browser works.
//
//   node web/verify.mjs      (run from crates/scylla-wasm/, or any cwd)
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const dir = dirname(fileURLToPath(import.meta.url));
const wasm = await WebAssembly.instantiate(readFileSync(join(dir, "scylla_wasm.wasm")), {});
const X = wasm.instance.exports;
const mem = X.memory;
const dec = new TextDecoder();

// A returned string is packed (ptr<<32 | len) in a u64 → copy it out of linear memory, then free.
const readStr = (p) => {
  const ptr = Number(p >> 32n), len = Number(p & 0xffffffffn);
  const bytes = new Uint8Array(mem.buffer, ptr, len).slice();
  X.scylla_free(ptr, len);
  return dec.decode(bytes);
};
const J = (p) => JSON.parse(readStr(p));

// Load the artifact through the alloc → load → free dance.
const art = readFileSync(join(dir, "mathlib.scylla"));
const ptr = X.scylla_alloc(art.length);
new Uint8Array(mem.buffer, ptr, art.length).set(art);
if (X.scylla_load(ptr, art.length) !== 0) throw new Error("artifact failed to load");
X.scylla_free(ptr, art.length);

const info = J(X.scylla_info());
const fns = J(X.scylla_functions(1));
const gcd = fns.find((f) => f.name === "gcd");
const callers = J(X.scylla_callers(BigInt(gcd.id))).map((cid) => J(X.scylla_view(BigInt(cid), 0)).name);

console.log("info       :", info);
console.log("functions  :", fns.map((f) => f.name).sort().join(", "));
console.log("view(gcd)  :", JSON.stringify((({ name, addr, bbCount, callees }) => ({ name, addr, bbCount, callees }))(J(X.scylla_view(BigInt(gcd.id), 1)))));
console.log("callers(gcd):", callers);

// Annotation round-trip: rename gcd in the browser, export the .scylla, reload it, and confirm
// the rename survived (durable user fact on the stable id — DD-005 + DD-026 persistence, in WASM).
const enc = new TextEncoder();
const passStr = (s) => {
  const b = enc.encode(s), p = X.scylla_alloc(b.length);
  new Uint8Array(mem.buffer, p, b.length).set(b);
  return [p, b.length];
};
const [np, nl] = passStr("euclid_gcd");
const rc = X.scylla_rename(BigInt(gcd.id), np, nl);
X.scylla_free(np, nl);

const ex = X.scylla_export();
const exPtr = Number(ex >> 32n), exLen = Number(ex & 0xffffffffn);
const exported = new Uint8Array(mem.buffer, exPtr, exLen).slice(); // the downloadable artifact
X.scylla_free(exPtr, exLen);

const rp = X.scylla_alloc(exported.length);
new Uint8Array(mem.buffer, rp, exported.length).set(exported);
X.scylla_load(rp, exported.length);
X.scylla_free(rp, exported.length);
const renamed = J(X.scylla_view(BigInt(gcd.id), 1)).name;
console.log("after rename → export → reload, gcd is now:", renamed, `(${exported.length}-byte artifact)`);

// Merge round-trip: re-anchor the rename onto a RE-ANALYSIS (same binary, fresh stable ids).
// merge_into matches functions by structural identity (not id), so the euclid_gcd rename should
// follow gcd across the rebuild — DD-005 identity-anchored merge, in the browser.
const rebuilt = readFileSync(join(dir, "mathlib_rebuilt.scylla"));
const mp = X.scylla_alloc(rebuilt.length);
new Uint8Array(mem.buffer, mp, rebuilt.length).set(rebuilt);
const report = J(X.scylla_merge(mp, rebuilt.length));
X.scylla_free(mp, rebuilt.length);
const reanchored = J(X.scylla_functions(1)).some((f) => f.name === "euclid_gcd");
console.log("merge report:", report, "| rename re-anchored onto the rebuild?", reanchored);

const ok =
  info.functions === fns.length &&
  callers.includes("main") &&
  rc === 0 &&
  renamed === "euclid_gcd" &&
  report.merged >= 1 &&
  reanchored;
console.log(ok ? "PASS — navigate + annotate + export + merge round-trip in WASM" : "FAIL");
process.exit(ok ? 0 : 1);
