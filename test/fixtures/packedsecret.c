/*
 * Blind-eval fixture for the dynamic plane: a passphrase gate packed with
 * UPX. The phrase is invisible twice over — section data is compressed by
 * the packer, and the phrase itself is XOR-encoded (key 0x5A) exactly like
 * xorsecret.c. The intended recovery path is dynamic_unpack (run briefly,
 * let pe-sieve dump the unpacked image from memory), then static analysis
 * of the dumped file. The sleep keeps the process alive inside the bounded
 * unpack window. Trusted fixture — never swap in untrusted samples.
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

static const unsigned char encoded[] = {
    0x37, 0x33, 0x34, 0x2f, 0x29, 0x35, 0x34, 0x3f, 0x77, 0x2a, 0x3b,
    0x39, 0x31, 0x3f, 0x3e, 0x77, 0x3d, 0x3b, 0x2e, 0x3f, 0x77, 0x3f,
    0x6e, 0x39, 0x68,
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
    printf("packed-gate-started\n");
    fflush(stdout);
    Sleep(20000);
    decode(phrase, sizeof(encoded));
    if (argc == 2 && strcmp(argv[1], phrase) == 0) {
        puts("access granted");
        return 0;
    }
    puts("access denied");
    return argc == 2 ? 1 : 2;
}
