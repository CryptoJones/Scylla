//! The DECOMPILATION leg of the A/B: the `decompile` verb (inside — the engine-service `Decompile`
//! RPC through the sandbox, `scylla decompile --json`) vs the raw engine's own decompiler output
//! (outside — `abtest/scripts/DumpDecomp.java` under a direct `analyzeHeadless`, the committed
//! `baselines/decomp/<bin>.decomp.txt`). Same dist, same `DecompInterface` configuration on both
//! legs, so the decompiled C must be byte-identical per function; any delta is the wrapper's.
//!
//! Both legs reduce to a list of [`DecompFunction`] keyed by entry address. The outside text format
//! is the dumper's: a `## LANGUAGE` header, then per function `==== FUNCTION <addr> <name> ====`,
//! `PROTO …`, `CCONV …`, `---- DECOMP ----`, the C verbatim, `---- ASM+PCODE ----`, the listing.
//! Only the fields the `decompile` verb carries are compared (name, prototype, calling
//! convention, the C, the failure message); the ASM+P-code section is the model leg's business.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::FieldMismatch;

/// One function's decompilation on either leg. Field names are the `scylla decompile --json` keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompFunction {
    pub entry: u64,
    pub name: String,
    pub prototype: String,
    pub calling_convention: String,
    /// The decompiler's C text verbatim (empty when `error` is set).
    pub c: String,
    /// The decompiler's failure message; empty on success.
    #[serde(default)]
    pub error: String,
}

/// The outside leg: the dumper's header plus its functions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DecompBaseline {
    /// The `## LANGUAGE <id> / <cspec>` header line's `<id>`.
    pub language: String,
    pub functions: Vec<DecompFunction>,
}

/// The parity report for one binary's decompilation. Empty vectors everywhere = parity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DecompReport {
    pub functions_inside: usize,
    pub functions_outside: usize,
    /// Entry addresses the `decompile` verb returned that the raw dump lacks.
    pub only_inside: Vec<u64>,
    /// Entry addresses the raw dump has that the `decompile` verb did not return.
    pub only_outside: Vec<u64>,
    /// Per-field disagreements on functions both legs have.
    pub field_mismatches: Vec<FieldMismatch>,
}

impl DecompReport {
    /// True only when both legs decompiled the same functions to the same text.
    pub fn is_parity(&self) -> bool {
        self.only_inside.is_empty()
            && self.only_outside.is_empty()
            && self.field_mismatches.is_empty()
    }
}

/// Parse the inside leg — `scylla decompile --json` output (an array of functions).
pub fn parse_inside(json: &str) -> Result<Vec<DecompFunction>, String> {
    serde_json::from_str(json).map_err(|e| e.to_string())
}

/// Parse a Ghidra address string to its offset: the text after the last `:` (a non-default
/// space prints qualified — `ram:00010500`), hex, `0x` optional. Same rule as `scylla_ingest`.
fn parse_addr(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let t = t.rsplit(':').next().unwrap_or(t);
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u64::from_str_radix(t, 16).map_err(|e| format!("bad address {s:?}: {e}"))
}

/// Parse the outside leg — the `DumpDecomp.java` text dump. The C section is reconstructed
/// byte-exactly: the dumper `print`s `getC()` (which ends in a newline) and then `println`s the
/// ASM marker, so the section's lines, each re-terminated, are the C verbatim.
pub fn parse_baseline(text: &str) -> Result<DecompBaseline, String> {
    let mut out = DecompBaseline::default();
    let mut cur: Option<DecompFunction> = None;
    let mut c_lines: Vec<&str> = Vec::new();
    // Where in a function block the parser is.
    #[derive(PartialEq)]
    enum At {
        Head,
        Decomp,
        Asm,
    }
    let mut at = At::Asm;
    let finish =
        |cur: &mut Option<DecompFunction>, c_lines: &mut Vec<&str>, out: &mut DecompBaseline| {
            if let Some(mut f) = cur.take() {
                let mut c = String::new();
                for l in c_lines.iter() {
                    c.push_str(l);
                    c.push('\n');
                }
                // A failed decompilation is one line: `<decompile-failed: msg>` — the verb reports it as
                // an error, not as C, so both legs land in the same field.
                let trimmed = c.trim_end_matches('\n');
                if let Some(msg) = trimmed
                    .strip_prefix("<decompile-failed: ")
                    .and_then(|r| r.strip_suffix('>'))
                {
                    if !trimmed.contains('\n') {
                        f.error = msg.to_string();
                        c = String::new();
                    }
                }
                f.c = c;
                out.functions.push(f);
                c_lines.clear();
            }
        };
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("==== FUNCTION ") {
            finish(&mut cur, &mut c_lines, &mut out);
            let body = rest
                .strip_suffix(" ====")
                .ok_or_else(|| format!("malformed function header: {line:?}"))?;
            let (addr, name) = body
                .split_once(' ')
                .ok_or_else(|| format!("malformed function header: {line:?}"))?;
            cur = Some(DecompFunction {
                entry: parse_addr(addr)?,
                name: name.to_string(),
                ..Default::default()
            });
            at = At::Head;
            continue;
        }
        match (&mut cur, &at) {
            (None, _) => {
                if let Some(rest) = line.strip_prefix("## LANGUAGE ") {
                    out.language = rest.split(" / ").next().unwrap_or(rest).trim().to_string();
                }
            }
            (Some(f), At::Head) => {
                if let Some(p) = line.strip_prefix("PROTO ") {
                    f.prototype = p.to_string();
                } else if let Some(cc) = line.strip_prefix("CCONV ") {
                    f.calling_convention = cc.to_string();
                } else if line == "---- DECOMP ----" {
                    at = At::Decomp;
                }
            }
            (Some(_), At::Decomp) => {
                if line == "---- ASM+PCODE ----" {
                    at = At::Asm;
                } else {
                    c_lines.push(line);
                }
            }
            (Some(_), At::Asm) => {} // the listing — not this leg's business
        }
    }
    finish(&mut cur, &mut c_lines, &mut out);
    Ok(out)
}

/// Compare the two legs. Pure: no I/O.
pub fn compare_decomp(inside: &[DecompFunction], outside: &[DecompFunction]) -> DecompReport {
    let by_addr = |fs: &[DecompFunction]| -> BTreeMap<u64, DecompFunction> {
        fs.iter().map(|f| (f.entry, f.clone())).collect()
    };
    let (a, b) = (by_addr(inside), by_addr(outside));
    let mut r = DecompReport {
        functions_inside: inside.len(),
        functions_outside: outside.len(),
        ..Default::default()
    };
    r.only_inside = a.keys().filter(|k| !b.contains_key(k)).copied().collect();
    r.only_outside = b.keys().filter(|k| !a.contains_key(k)).copied().collect();
    for (addr, x) in &a {
        let Some(y) = b.get(addr) else { continue };
        let mut push = |field: &'static str, p: &str, q: &str| {
            if p != q {
                r.field_mismatches.push(FieldMismatch {
                    addr: *addr,
                    name: x.name.clone(),
                    field,
                    inside: p.to_string(),
                    outside: q.to_string(),
                });
            }
        };
        push("name", &x.name, &y.name);
        push("prototype", &x.prototype, &y.prototype);
        push(
            "calling_convention",
            &x.calling_convention,
            &y.calling_convention,
        );
        push("c", &x.c, &y.c);
        push("error", &x.error, &y.error);
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    // concat! (not a `\`-continued literal) so the C body's leading indentation survives verbatim.
    const DUMP: &str = concat!(
        "## LANGUAGE x86:LE:64:default / gcc\n",
        "## IMAGEBASE 00400000\n",
        "## FUNCTIONS 2\n",
        "\n",
        "==== FUNCTION 00401000 _init ====\n",
        "PROTO int _init(EVP_PKEY_CTX * ctx)\n",
        "CCONV __stdcall\n",
        "---- DECOMP ----\n",
        "\n",
        "int _init(EVP_PKEY_CTX *ctx)\n",
        "\n",
        "{\n",
        "  return 1;\n",
        "}\n",
        "\n",
        "---- ASM+PCODE ----\n",
        "00401000: ENDBR64\n",
        "00401004: SUB RSP,0x8\n",
        "    (register, 0x200, 1) INT_LESS (register, 0x20, 8) , (const, 0x8, 8)\n",
        "\n",
        "==== FUNCTION ram:00010500 rustmath::gcd ====\n",
        "PROTO int gcd(int a, int b)\n",
        "CCONV __rustcall\n",
        "---- DECOMP ----\n",
        "<decompile-failed: timed out>\n",
        "---- ASM+PCODE ----\n",
        "00010500: RET\n",
    );

    #[test]
    fn baseline_parses_header_functions_and_byte_exact_c() {
        let b = parse_baseline(DUMP).unwrap();
        assert_eq!(b.language, "x86:LE:64:default");
        assert_eq!(b.functions.len(), 2);
        let f = &b.functions[0];
        assert_eq!(f.entry, 0x401000);
        assert_eq!(f.name, "_init");
        assert_eq!(f.prototype, "int _init(EVP_PKEY_CTX * ctx)");
        assert_eq!(f.calling_convention, "__stdcall");
        assert_eq!(
            f.c,
            "\nint _init(EVP_PKEY_CTX *ctx)\n\n{\n  return 1;\n}\n\n"
        );
        assert!(f.error.is_empty());
        // Space-qualified address, namespaced name, and a failed decompilation → error, not C.
        let g = &b.functions[1];
        assert_eq!(g.entry, 0x10500);
        assert_eq!(g.name, "rustmath::gcd");
        assert_eq!(g.error, "timed out");
        assert!(g.c.is_empty());
    }

    #[test]
    fn identical_legs_are_parity_and_a_changed_body_is_not() {
        let outside = parse_baseline(DUMP).unwrap().functions;
        let inside_json = serde_json::to_string(&outside).unwrap();
        let inside = parse_inside(&inside_json).unwrap();
        assert!(compare_decomp(&inside, &outside).is_parity());

        let mut drifted = inside.clone();
        drifted[0].c = drifted[0].c.replace("return 1", "return 2");
        drifted.pop();
        let r = compare_decomp(&drifted, &outside);
        assert!(!r.is_parity());
        assert_eq!(r.only_outside, vec![0x10500]);
        assert_eq!(r.field_mismatches.len(), 1);
        assert_eq!(r.field_mismatches[0].field, "c");
        assert_eq!(r.field_mismatches[0].addr, 0x401000);
    }

    #[test]
    fn inside_json_without_error_key_still_parses() {
        // `error` defaults: an older/foreign producer omitting it is a success record.
        let v = parse_inside(
            r#"[{"entry": 4096, "name": "f", "prototype": "void f(void)", "calling_convention": "__stdcall", "c": "void f(void)\n{\n}\n"}]"#,
        )
        .unwrap();
        assert_eq!(v[0].entry, 4096);
        assert!(v[0].error.is_empty());
    }
}
