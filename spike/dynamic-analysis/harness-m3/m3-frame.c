/* m3-frame — frame a JSON trace (on stdin) into the M2 channel format (on stdout).
 *
 * The in-guest observer (m3-observe.sh's /init) recovers a resolved IAT and pipes the JSON trace
 * here; this emits the SCYLLA-TRACE-V1 frame the host reader (../src/channel.rs) validates. The
 * base64 alphabet, the FNV-1a-64, and the 4096-col wrap MATCH channel.rs byte-for-byte. Tiny + std
 * libc only, so it shares the sample's ld.so/libc in the initramfs (no extra deps). NOT hostile,
 * runs INSIDE the contained microVM. */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static const char T[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int main(void) {
    size_t cap = 262144, n = 0; /* bound the read to the host's decoded cap */
    unsigned char *b = malloc(cap);
    if (!b) return 1;
    int c;
    while ((c = getchar()) != EOF && n < cap) b[n++] = (unsigned char)c;

    uint64_t h = 0xcbf29ce484222325ULL; /* FNV-1a-64 offset basis (matches channel.rs) */
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 0x100000001b3ULL; }

    fputs("SCYLLA-TRACE-V1 BEGIN\n", stdout);
    size_t col = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t b0 = b[i];
        uint32_t b1 = i + 1 < n ? b[i + 1] : 0;
        uint32_t b2 = i + 2 < n ? b[i + 2] : 0;
        uint32_t v = (b0 << 16) | (b1 << 8) | b2;
        putchar(T[(v >> 18) & 63]);
        putchar(T[(v >> 12) & 63]);
        putchar(i + 1 < n ? T[(v >> 6) & 63] : '=');
        putchar(i + 2 < n ? T[v & 63] : '=');
        if ((col += 4) >= 4096) { putchar('\n'); col = 0; }
    }
    if (col) putchar('\n');
    printf("SCYLLA-TRACE-V1 END len=%zu fnv=%016llx\n", n, (unsigned long long)h);
    return 0;
}
