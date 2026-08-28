/*
 * Blind-eval fixture for the full-investigation scenario: a passphrase gate
 * packed with UPX whose phrase is XOR-encoded (key 0x5A) like xorsecret.c.
 * The intended chain spans every plane: packer triage, dynamic_unpack (the
 * dumped image still holds the ENCODED blob — the sleep keeps the process
 * inside the scan window before decode runs), dumps_floss over the dump
 * directory to emulate the decode routine, and report_correlate over the
 * same dumps. The drop file only appears after the sleep, so the bounded
 * unpack window never leaks the plaintext phrase to disk. Trusted fixture —
 * never swap in untrusted samples.
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

static const unsigned char encoded[] = {
    0x37, 0x33, 0x34, 0x2f, 0x29, 0x35, 0x34, 0x3f, 0x77, 0x3c, 0x2f,
    0x36, 0x36, 0x77, 0x39, 0x3b, 0x29, 0x3f, 0x77, 0x38, 0x63, 0x6b,
    0x3e,
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
    printf("fullcase-started\n");
    fflush(stdout);
    Sleep(20000);
    decode(phrase, sizeof(encoded));
    FILE *drop = fopen("fullcase-drop.txt", "w");
    if (drop != NULL) {
        fprintf(drop, "recovered phrase: %s\n", phrase);
        fclose(drop);
    }
    if (argc == 2 && strcmp(argv[1], phrase) == 0) {
        puts("access granted");
        return 0;
    }
    puts("access denied");
    return argc == 2 ? 1 : 2;
}
