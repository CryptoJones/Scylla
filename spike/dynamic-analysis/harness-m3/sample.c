/* A benign, dynamically-linked sample with a KNOWN import set — the ground truth M3's observer must
 * recover. It calls a handful of libc functions (puts / getpid / snprintf / strlen); at runtime the
 * dynamic linker resolves them, which is exactly the "resolved IAT" a dynamic producer rebuilds for a
 * packed/stripped sample whose imports static analysis can't see. Nothing hostile — it prints a line
 * and exits. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char buf[64];
    snprintf(buf, sizeof buf, "sample pid=%d len=%zu", (int)getpid(), strlen("scylla"));
    puts(buf);
    return 0;
}
