#!/usr/bin/env python3
"""Scylla re-anchoring spike (DD-004/005).

Match v1 functions to v2 functions by STRUCTURE ALONE (name-agnostic), then measure how
many of an analyst's facts would survive re-analysis. Symbol names are used ONLY as ground
truth to score — never as a matching signal (real targets are stripped).

v2 (2026-06-21): (a) exclude identified runtime/library functions from the candidate pool
(a real tool does this via FLIRT/signatures; here proxied by name); (b) add an ordered
mnemonic-trigram signal; (c) apply a confidence threshold so a weak best-match becomes
*orphaned* (flagged for review) instead of a silent *wrong* re-anchor. Orphaned is a SAFE
failure under DD-005 (surface it, don't clobber); WRONG is the dangerous one.

Usage: reanchor.py <v1.json> <v2.json> [label] [threshold]
"""
import json
import math
import sys
from collections import Counter

SOURCE_FUNCS = {
    "gcd", "fib", "factorial", "sum_to", "main", "lcm",
    "my_strlen", "my_reverse", "count_vowels",
}

# Runtime/CRT functions a real tool would identify and set aside (signature/loader);
# here proxied by name. Anything starting with "_" is also treated as runtime.
RUNTIME_FUNCS = {
    "deregister_tm_clones", "register_tm_clones", "frame_dummy", "abort",
    "atexit", "call_weak_fn",
}


def is_runtime(name):
    return name in RUNTIME_FUNCS or name.startswith("_")


def load(path):
    d = json.load(open(path))
    callers = Counter()
    for f in d["functions"]:
        for c in f["callees"]:
            callers[c] += 1
    for f in d["functions"]:
        f["_mnem"] = Counter(f["mnemonics"])
        f["_tri"] = trigrams(f["mnemonics"])
        f["_ncallee"] = len(f["callees"])
        f["_ncaller"] = callers[f["entry"]]
    return d


def trigrams(mnems):
    if len(mnems) < 3:
        return {tuple(mnems)}
    return {tuple(mnems[i:i + 3]) for i in range(len(mnems) - 2)}


def cosine(c1, c2):
    keys = set(c1) | set(c2)
    dot = sum(c1.get(k, 0) * c2.get(k, 0) for k in keys)
    n1 = math.sqrt(sum(v * v for v in c1.values()))
    n2 = math.sqrt(sum(v * v for v in c2.values()))
    return dot / (n1 * n2) if n1 and n2 else 0.0


def jaccard(s1, s2):
    u = s1 | s2
    return len(s1 & s2) / len(u) if u else 1.0


def closeness(x, y):
    return 1.0 - abs(x - y) / max(1, x + y)


def sim(a, b):
    cm = cosine(a["_mnem"], b["_mnem"])          # instruction mix
    tj = jaccard(a["_tri"], b["_tri"])           # ordered local patterns
    cb = closeness(a["bb_count"], b["bb_count"])  # CFG shape
    cc = closeness(a["_ncallee"], b["_ncallee"])  # out-degree
    cr = closeness(a["_ncaller"], b["_ncaller"])  # in-degree
    return 0.40 * cm + 0.30 * tj + 0.15 * cb + 0.10 * cc + 0.05 * cr


def best_match(a, candidates):
    best, score = None, -1.0
    for b in candidates:
        s = sim(a, b)
        if s > score:
            score, best = s, b
    return best, score


def main():
    v1p, v2p = sys.argv[1], sys.argv[2]
    label = sys.argv[3] if len(sys.argv) > 3 else "%s -> %s" % (v1p, v2p)
    threshold = float(sys.argv[4]) if len(sys.argv) > 4 else 0.55
    v1, v2 = load(v1p), load(v2p)

    candidates = [f for f in v2["functions"] if not is_runtime(f["name"])]
    annotated = [f for f in v1["functions"] if f["name"] in SOURCE_FUNCS]

    correct = wrong = orphaned = 0
    rows = []
    for a in annotated:
        b, s = best_match(a, candidates)
        if b is None or s < threshold:
            verdict, tgt = "ORPHAN", (b["name"] if b else "-")
            orphaned += 1
        elif b["name"] == a["name"]:
            verdict, tgt = "OK", b["name"]
            correct += 1
        else:
            verdict, tgt = "WRONG", b["name"]
            wrong += 1
        rows.append((a["name"], tgt, "%.2f" % s, verdict))

    total = len(annotated)
    rate = 100.0 * correct / total if total else 0.0
    print("== %s ==" % label)
    for r in rows:
        print("  %-12s -> %-12s sim=%s  %s" % r)
    print("  SUMMARY | %-30s | OK=%d WRONG=%d ORPHAN=%d /%d  survived=%.0f%%"
          % (label, correct, wrong, orphaned, total, rate))


if __name__ == "__main__":
    main()
