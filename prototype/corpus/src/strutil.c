/* strutil — a second small program (distinct call graph) for the spike. */
#include <stdio.h>
#include <string.h>

static unsigned my_strlen(const char *s) {
    unsigned n = 0;
    while (s[n]) n++;
    return n;
}

static void my_reverse(char *s) {
    unsigned n = my_strlen(s);
    for (unsigned i = 0; i < n / 2; i++) {
        char t = s[i]; s[i] = s[n - 1 - i]; s[n - 1 - i] = t;
    }
}

static unsigned count_vowels(const char *s) {
    unsigned c = 0;
    for (unsigned i = 0; s[i]; i++) {
        char ch = s[i] | 32;
        if (ch=='a'||ch=='e'||ch=='i'||ch=='o'||ch=='u') c++;
    }
    return c;
}

int main(int argc, char **argv) {
    char buf[256];
    const char *src = argc > 1 ? argv[1] : "reverse engineering";
    strncpy(buf, src, sizeof buf - 1);
    buf[sizeof buf - 1] = 0;
    printf("len=%u vowels=%u\n", my_strlen(buf), count_vowels(buf));
    my_reverse(buf);
    printf("reversed=%s\n", buf);
    return 0;
}
