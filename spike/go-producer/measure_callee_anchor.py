#!/usr/bin/env python3
"""Scylla Go-aware producer de-risk (DD-043).

A faithful Python replica of the shipping four-pass re-anchoring matcher (exact -> arch-independent
anchor -> reciprocal fuzzy -> call-graph propagation), with ONE change: the anchor set is extended
with CALLEE NAMES (the names of called functions). On Go these survive stripping (pclntab) and are
arch-independent; on stripped C they would be FUN_* placeholders and contribute nothing.

Run two snapshots of the SAME program built for different architectures and it reports cross-arch
recovery + WRONG count. Usage: measure_callee_anchor.py <source.json> <dest.json>
"""
import json
import math
import sys
from collections import Counter, defaultdict

GOSRC = {"main.gcd", "main.fib", "main.factorial", "main.sumTo", "main.main"}


def load(path):
    fs = json.load(open(path))["functions"]
    addrs = {f["entry"] for f in fs}
    byaddr = {f["entry"]: f["name"] for f in fs}
    for f in fs:
        f["_callees"] = [c for c in f.get("callees", []) if c in addrs]
        f["_hist"] = Counter(f.get("mnemonics", []))
        callee_names = {byaddr.get(c) for c in f.get("callees", [])} - {None}
        # DD-043: callee NAMES join the arch-independent anchor set (Go pclntab names survive
        # stripping; FUN_* placeholders on stripped C would add nothing).
        callee_names = {n for n in callee_names if not n.startswith("FUN_")}
        f["_aset"] = set(f.get("string_refs", [])) | set(f.get("imports", [])) | callee_names
    return fs


def sig(f):
    return (f["bb_count"], f["size"], len(f["_callees"]), tuple(sorted(f["_hist"].items())))


def cos(a, b):
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b.get(k, 0) for k in a)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def close(x, y):
    return 1.0 - abs(x - y) / max(x + y, 1)


def sim(a, b):
    return (0.60 * cos(a["_hist"], b["_hist"])
            + 0.25 * close(a["bb_count"], b["bb_count"])
            + 0.15 * close(len(a["_callees"]), len(b["_callees"])))


def jac(a, b):
    return len(a & b) / len(a | b) if a and b else 0.0


def callers(fs):
    m = defaultdict(list)
    for f in fs:
        for c in f["_callees"]:
            m[c].append(f["entry"])
    return m


def merge(o0, o2):
    o0b = {f["entry"]: f for f in o0}
    o2b = {f["entry"]: f for f in o2}
    o0c, o2c = callers(o0), callers(o2)
    bysig = defaultdict(list)
    for f in o2:
        bysig[sig(f)].append(f["entry"])
    matched, claimed = {}, set()
    targets = [f["entry"] for f in o0 if f["name"] in GOSRC]

    deferred = []
    for t in targets:  # exact
        m = bysig.get(sig(o0b[t]), [])
        if len(m) == 1:
            matched[t] = m[0]
            claimed.add(m[0])
        else:
            deferred.append(t)

    d2 = []
    for t in deferred:  # anchor (Jaccard over the extended set)
        a = o0b[t]["_aset"]
        if len(a) < 2:
            d2.append(t)
            continue
        best, b1, b2 = None, -1, -1
        for g in o2:
            if g["entry"] in claimed:
                continue
            s = jac(a, g["_aset"])
            if s > b1:
                b2, b1, best = b1, s, g["entry"]
            elif s > b2:
                b2 = s
        if best and b1 >= 0.5 and b1 - b2 >= 0.25:
            matched[t] = best
            claimed.add(best)
        else:
            d2.append(t)

    def best_old(g):
        bb, bv = None, -1
        for f in o0:
            s = sim(f, g)
            if s > bv:
                bv, bb = s, f["entry"]
        return bb

    d3 = []
    for t in d2:  # reciprocal fuzzy
        of = o0b[t]
        best, b1, b2 = None, -1, -1
        for g in o2:
            if g["entry"] in claimed:
                continue
            s = sim(of, g)
            if s > b1:
                b2, b1, best = b1, s, g["entry"]
            elif s > b2:
                b2 = s
        if best and b1 >= 0.55 and b1 - b2 >= 0.05 and best_old(o2b[best]) == t:
            matched[t] = best
            claimed.add(best)
        else:
            d3.append(t)

    changed = True
    while changed:  # call-graph propagation
        changed = False
        for t in d3:
            if t in matched:
                continue
            b = o0b[t]
            ci = [matched[c] for c in o0c.get(t, []) if c in matched]
            ei = [matched[c] for c in b["_callees"] if c in matched]
            if not ci and not ei:
                continue
            cands = set()
            for x in ci:
                cands |= set(o2b[x]["_callees"])
            for x in ei:
                cands |= set(o2c.get(x, []))
            brec = t in b["_callees"]
            best, b1, b2 = None, -1, -1
            for cand in cands:
                if cand in claimed:
                    continue
                cf = o2b[cand]
                ca = sum(1 for x in ci if cand in o2b[x]["_callees"])
                cea = sum(1 for x in ei if x in cf["_callees"])
                rec = 2.0 if (brec and cand in cf["_callees"]) else 0.0
                s = ca + cea + rec
                if s > b1:
                    b2, b1, best = b1, s, cand
                elif s > b2:
                    b2 = s
            if best and b1 - max(b2, 1.0) >= 1.0:
                matched[t] = best
                claimed.add(best)
                changed = True

    nm = lambda fs, e: next((f["name"] for f in fs if f["entry"] == e), "?")
    correct = [o0b[t]["name"] for t in targets if nm(o2, matched.get(t, -1)) == o0b[t]["name"]]
    wrong = [(o0b[t]["name"], nm(o2, matched[t])) for t in targets
             if t in matched and nm(o2, matched[t]) != o0b[t]["name"]]
    return correct, len(targets), wrong


if __name__ == "__main__":
    src, dst = load(sys.argv[1]), load(sys.argv[2])
    correct, total, wrong = merge(src, dst)
    print(f"Go cross-arch WITH callee-names: {len(correct)}/{total} "
          f"recovered={correct} WRONG={wrong}")
    if wrong:
        print("FAIL: WRONG > 0")
        sys.exit(1)
