/*
 * MBA (mixed boolean arithmetic) obfuscation fixture: expressions every
 * deobfuscator aims to collapse, plus a flattened-style dispatcher switch.
 * Semantics: returns 1 when the serial's checksum equals 0x5a5a5a5a mod 2^32.
 */
#include <stdint.h>
#include <string.h>

static uint32_t mba_add(uint32_t a, uint32_t b) {
    /* a + b == (a ^ b) + 2 * (a & b) */
    return (a ^ b) + 2 * (a & b);
}

static uint32_t mba_sub(uint32_t a, uint32_t b) {
    /* a - b == (a ^ ~b) + 2 * (a & ~b) + 1 */
    return (a ^ ~b) + 2 * (a & ~b) + 1;
}

static uint32_t mba_or(uint32_t a, uint32_t b) {
    /* a | b == a + b - (a & b) */
    return mba_sub(mba_add(a, b), a & b);
}

static int flattened_check(const char *s) {
    uint32_t state = 0;
    uint32_t acc = 0;
    int i = 0;
    while (1) {
        switch (state) {
            case 0:
                if (s[i] == 0) { state = 3; }
                else { state = 1; }
                continue;
            case 1:
                acc = mba_or(mba_add(acc, (uint32_t)s[i]), 0x1337);
                i++;
                state = (uint32_t)(i & 7) == 0 ? 2 : 0;
                continue;
            case 2:
                acc = mba_sub(acc, (uint32_t)(i * 3));
                state = 0;
                continue;
            case 3:
            default:
                return acc == 0x5a5a5a5a;
        }
    }
}

int main(int argc, char **argv) {
    if (argc < 2) return 0;
    return flattened_check(argv[1]);
}
