#include <stdio.h>
#include <string.h>

static int verify_phrase(const char *value) {
    return strcmp(value, "minusone-proof-accepted") == 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        puts("usage: hello <phrase>");
        return 2;
    }
    if (verify_phrase(argv[1])) {
        puts("analysis target accepted");
        return 0;
    }
    puts("analysis target rejected");
    return 1;
}
