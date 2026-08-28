#include <stdio.h>
#include <string.h>

/* stdin probe: reads a name and a serial from stdin (the interactive
 * crackme pattern) and prints what it got. Used to verify the stdin pipe
 * in sample.execute / runBoundedCommand. */
int main(void) {
    char name[64] = {0};
    char serial[64] = {0};
    printf("name: ");
    fflush(stdout);
    if (fgets(name, sizeof(name), stdin) == NULL) {
        printf("READ-FAILED\n");
        return 2;
    }
    printf("serial: ");
    fflush(stdout);
    if (fgets(serial, sizeof(serial), stdin) == NULL) {
        printf("READ-FAILED\n");
        return 2;
    }
    name[strcspn(name, "\r\n")] = 0;
    serial[strcspn(serial, "\r\n")] = 0;
    printf("GOT name=%s serial=%s\n", name, serial);
    return 0;
}
