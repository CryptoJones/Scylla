#!/usr/bin/env python3
"""Scylla re-anchoring spike (DD-004/005).

Match v1 functions to v2 functions by STRUCTURE ALONE (name-agnostic), then measure
how many of an analyst's facts would survive re-analysis. Symbol names are used ONLY as
ground truth to score the match — never as a matching signal (real targets are stripped).

Usage: reanchor.py <v1.json> <v2.json> [label]
"""
import json
import math
import sys
from collections import Counter

# Functions an analyst would actually annotate (the source-defined ones).
SOURCE_FUNCS = {
    "gcd", "fib", "factorial", "sum_to", "main", "lcm",
    "my_strlen", "my_reverse", "count_vowels",
}


def load(path):
    d = json.load(open(path))
    callers = Counter()
    for f in d["functions"]:
        for c in f["callees"]:
            callers[c] += 1
    for f in d["functions"]:
        f["_mnem"] = Counter(f["mnemonics"])
        f["_ncallee"] = len(f["callees"])
        f["_ncaller"] = callers[f["entry"]]
    return d


def cosine(c1, c2):
    keys = set(c1) | set(c2)
    dot = sum(c1.get(k, 0) * c2.get(k, 0) for k in keys)
    n1 = math.sqrt(sum(v * v for v in c1.values()))
    n2 = math.sqrt(sum(v * v for v in c2.values()))
    return dot / (n1 * n2) if n1 and n2 else 0.0


def closeness(x, y):
    return 1.0 - abs(x - y) / max(1, x + y)


def sim(a, b):
    # mnemonic-mix cosine dominates same-arch; graph terms carry cross-arch.
    cm = cosine(a["_mnem"], b["_mnem"])
    cb = closeness(a["bb_count"], b["bb_count"])
    cc = closeness(a["_ncallee"], b["_ncallee"])
    cr = closeness(a["_ncaller"], b["_ncaller"])
    return 0.60 * cm + 0.18 * cb + 0.12 * cc + 0.10 * cr


def best_match(a, v2funcs):
    best, score = None, -1.0
    for b in v2funcs:
        s = sim(a, b)
        if s > score:
            score, best = s, b
    return best, score


def main():
    v1p, v2p = sys.argv[1], sys.argv[2]
    label = sys.argv[3] if len(sys.argv) > 3 else "%s -> %s" % (v1p, v2p)
    v1, v2 = load(v1p), load(v2p)
    annotated = [f for f in v1["functions"] if f["name"] in SOURCE_FUNCS]
    correct = 0
    rows = []
    for a in annotated:
        b, s = best_match(a, v2["functions"])
        ok = b is not None and b["name"] == a["name"]
        correct += 1 if ok else 0
        rows.append((a["name"], b["name"] if b else "-", "%.2f" % s, "OK" if ok else "MISS"))
    total = len(annotated)
    rate = 100.0 * correct / total if total else 0.0
    print("== %s ==" % label)
    for r in rows:
        print("  %-12s -> %-12s sim=%s  %s" % r)
    print("  SUMMARY | %-34s | survived=%d/%d (%.0f%%)" % (label, correct, total, rate))


if __name__ == "__main__":
    main()
