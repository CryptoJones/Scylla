/* From CryptoJones/ghidra-difftest corpus/src/constructs.c (the GayHydra-vs-upstream characterization harness), reused verbatim for the Scylla A/B parity corpus. */
/* constructs.c — exercises decompiler-relevant control/data flow.
 * Deliberately broad: loops, switch jump-tables, structs/unions/bitfields,
 * pointers, function pointers, recursion, varargs, globals/statics. */
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

int g_counter = 7;
static long s_accum;

struct point { int x, y; };
union packed { uint32_t u; struct { uint16_t lo, hi; } w; uint8_t b[4]; };
struct flags { unsigned a : 1, b : 3, c : 4, d : 24; };

static long recurse(long n) { return n < 2 ? n : recurse(n - 1) + recurse(n - 2); }

static int classify(int v) {                 /* dense switch -> jump table */
    switch (v) {
        case 0: return 100;
        case 1: return 101;
        case 2: return 102;
        case 3: return 103;
        case 4: return 104;
        case 5: return 105;
        case 6: return 106;
        case 7: return 107;
        default: return -1;
    }
}

static int apply(int (*fn)(int), int x) { return fn(x); }
static int dbl(int x) { return x << 1; }

static long sum_va(int n, ...) {
    va_list ap; long t = 0; va_start(ap, n);
    for (int i = 0; i < n; i++) t += va_arg(ap, int);
    va_end(ap);
    return t;
}

static void munge(struct point *p, int k) {
    for (int i = 0; i < k; i++) { p->x += i; p->y ^= (p->x << 1); }
}

int compute(int seed) {
    struct point p = { seed, seed * 3 };
    union packed u; u.u = (uint32_t)(seed * 2654435761u);
    struct flags f = { 1, seed & 7, seed & 15, seed };
    long r = recurse(12);
    r += classify(seed & 7);
    r += apply(dbl, seed);
    r += sum_va(4, seed, seed + 1, seed + 2, seed + 3);
    munge(&p, seed & 31);
    s_accum += r + p.x + p.y + u.w.lo + u.b[3] + f.b + f.d;
    g_counter ^= (int)r;
    return (int)(s_accum ^ g_counter);
}

int main(int argc, char **argv) {
    int acc = 0;
    for (int i = 1; i < argc; i++) acc += compute((int)strlen(argv[i]) + i);
    printf("acc=%d counter=%d accum=%ld\n", acc, g_counter, s_accum);
    return acc & 0xff;
}
