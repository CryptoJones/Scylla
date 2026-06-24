# M5.1 follow-on finding — packing defeats PLT interception; syscall tracing survives

A de-risk result that **bounds M5.1's observer** and shapes M5.3's design. Run on a *benign* binary
(`m5_1-packed.sh`); no malware.

## The experiment

Compile a benign sample with clear libc imports (`getpid`/`puts`/`snprintf`), UPX-pack it, then look at
its imports three ways:

| Lens | Unpacked | **Packed** |
|---|---|---|
| **Static** (`readelf --dyn-syms`, UND) | 10 | **0** — packer hides the import table |
| **PLT interception** (`ltrace`, M5.1's observer, `LD_DEBUG` unset) | recovers `getpid`/`puts`/`snprintf` | **0** — defeated |
| **Syscall trace** (`strace`) | full syscall behavior | **22 syscalls** incl. `getpid()` + `write(1,"pid=…")` — **survives** |

## Why PLT interception is defeated by packing

`ltrace` sets breakpoints on the binary's **PLT stubs** to catch library calls. A UPX-packed binary is a
small decompressor **stub** with *no* PLT — the original program (and its real PLT/GOT) only
materializes in memory **after** the stub decompresses it and jumps in, at runtime. So the breakpoints
`ltrace` places on the static (empty) PLT never fire. Static analysis fails for the same reason (the
import table isn't in the file), and **M3's `LD_DEBUG`** fails too (the loader binds the *stub*, not the
unpacked program). So all three import-table approaches are blind to a packed sample.

## Why syscall tracing survives

The unpacked program still has to talk to the kernel. `strace` (ptrace `PTRACE_SYSCALL`, or a seccomp
notifier, or a QEMU-user/eBPF syscall tap) observes the boundary the sample **cannot avoid** — so it
recovers the real behavior (here: `getpid()`, then `write(1, "pid=3331501 len=6\n")`) regardless of
packing. It yields a *behavioral* trace (syscalls), not the named IAT — a different, coarser, but
**packing- and obfuscation-resistant** observation.

## What this means for the harness

- **M5.1's observer (PLT interception) is the *benign-IAT* path** — correct for cooperative,
  unpacked samples, and it already runs in the Firecracker tier. It is **not** sufficient for packed
  samples.
- **M5.3 (real malware) needs a SYSCALL-level observer** as well — malware is routinely packed, so the
  packing-resistant layer is the load-bearing one there. Candidates, in tier-friendliness order:
  ptrace-`PTRACE_SYSCALL` (works today), a seccomp-unotify tap, or QEMU-user/eBPF tracing.
- **Provenance unchanged:** a syscall trace is still a partial-coverage dynamic observation — stamped
  `producer="dynamic"`, `confidence < 100` (DD-007), down-rankable by DD-027, never ground truth.
  GAP-8 (evasion: a sample can detect ptrace/strace and behave differently) is inherent and recorded,
  exactly as for the IAT observer.

So the honest takeaway: M5.1 de-risked the *uncooperative-loader* case; this de-risks the *packed*
case and shows the observer M5.3 must add. Both findings push the same way — observations stay
untrusted and confidence-stamped; the matcher (`WRONG = 0`) is never fed ground truth.

Reproduce: `./m5_1-packed.sh` (exit 0).

---

*Proudly Made in Nebraska. Go Big Red! 🌽 https://xkcd.com/2347/*
