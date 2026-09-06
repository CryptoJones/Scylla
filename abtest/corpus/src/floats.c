/* From CryptoJones/ghidra-difftest corpus/src/floats.c (the GayHydra-vs-upstream characterization harness), reused verbatim for the Scylla A/B parity corpus. */
/* floats.c — FP and 64-bit integer math; stresses decompiler type/width recovery. */
#include <stdio.h>
#include <stdint.h>
#include <math.h>

double poly(double x) { return ((3.0*x - 2.5)*x + 1.25)*x - 0.5; }

float mix(float a, float b, float t) { return a + (b - a) * t; }

uint64_t mul_hi(uint64_t a, uint64_t b) {
    __uint128_t p = (__uint128_t)a * b;   /* 128-bit -> hi/lo split */
    return (uint64_t)(p >> 64);
}

int64_t sat_add(int64_t a, int64_t b) {
    int64_t r;
    if (__builtin_add_overflow(a, b, &r)) return a < 0 ? INT64_MIN : INT64_MAX;
    return r;
}

double accumulate(const double *v, int n) {
    double s = 0.0, c = 0.0;              /* Kahan summation */
    for (int i = 0; i < n; i++) { double y = v[i] - c, t = s + y; c = (t - s) - y; s = t; }
    return s;
}

int main(void) {
    double v[8]; for (int i = 0; i < 8; i++) v[i] = poly(i * 0.5);
    double s = accumulate(v, 8);
    float m = mix(1.0f, 9.0f, 0.25f);
    uint64_t h = mul_hi(0x123456789ULL, 0xfedcba987ULL);
    int64_t sa = sat_add(INT64_MAX - 3, 10);
    printf("s=%.6f m=%.3f h=%llu sa=%lld sqrt=%.4f\n",
           s, (double)m, (unsigned long long)h, (long long)sa, sqrt(fabs(s)));
    return (int)(h & 0x7f);
}
