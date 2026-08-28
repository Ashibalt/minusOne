#include <stdio.h>
#include <string.h>

/*
 * Blind-eval fixture: the access phrase is never stored in plaintext.
 * It lives in .rodata XOR-encoded with the single byte 0x5A and is
 * decoded onto the stack only for comparison. Static analysis must
 * recover the phrase from the decode loop; string dumps cannot.
 */
static const unsigned char encoded[] = {
    0x37, 0x33, 0x34, 0x2f, 0x29, 0x35, 0x34, 0x3f, 0x77, 0x22, 0x35,
    0x28, 0x77, 0x3d, 0x3b, 0x2e, 0x3f, 0x77, 0x6d, 0x3c, 0x69, 0x3b,
};
static const unsigned char xor_key = 0x5A;

static void decode(char *out, size_t length) {
    for (size_t i = 0; i < length; i++) {
        out[i] = (char)(encoded[i] ^ xor_key);
    }
    out[length] = '\0';
}

int main(int argc, char **argv) {
    char phrase[64];
    if (argc != 2) {
        puts("usage: xorsecret <phrase>");
        return 2;
    }
    decode(phrase, sizeof(encoded));
    if (strcmp(argv[1], phrase) == 0) {
        puts("access granted");
        return 0;
    }
    puts("access denied");
    return 1;
}
