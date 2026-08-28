#include <stdio.h>

int main(void) {
    printf("SLEEPING\n");
    fflush(stdout);
    for (;;) { }
}
