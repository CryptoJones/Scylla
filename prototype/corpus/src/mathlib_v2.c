/* mathlib_v2 — the perturbed twin of mathlib: an lcm() function is inserted
 * (built on gcd) and the order is changed, shifting addresses + boundaries of
 * everything below it. This is the structural change re-anchoring must survive. */
#include <stdio.h>
#include <stdlib.h>

static unsigned long gcd(unsigned long a, unsigned long b) {
    while (b) { unsigned long t = b; b = a % b; a = t; }
    return a;
}

/* NEW in v2 */
static unsigned long lcm(unsigned long a, unsigned long b) {
    if (a == 0 || b == 0) return 0;
    return a / gcd(a, b) * b;
}

static unsigned long factorial(unsigned n) {
    unsigned long r = 1;
    for (unsigned i = 2; i <= n; i++) r *= i;
    return r;
}

static unsigned long fib(unsigned n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

static unsigned long sum_to(unsigned n) {
    unsigned long s = 0;
    for (unsigned i = 1; i <= n; i++) s += i;
    return s;
}

int main(int argc, char **argv) {
    unsigned n = argc > 1 ? (unsigned)atoi(argv[1]) : 10;
    printf("gcd(%u,48)=%lu\n", n, gcd(n, 48));
    printf("lcm(%u,48)=%lu\n", n, lcm(n, 48));
    printf("fib(%u)=%lu\n", n, fib(n));
    printf("fact(%u)=%lu\n", n, factorial(n));
    printf("sum(%u)=%lu\n", n, sum_to(n));
    return 0;
}
