/* Trusted dynamic-plane fixture for the Frida probe: rewrites a note file
 * every second for ~20s, so API hooks installed after attach have steady
 * traffic to observe inside the probe window. */
#include <stdio.h>
#include <windows.h>

int main(void) {
    for (int beat = 0; beat < 20; beat++) {
        FILE *note = fopen("frida-note.txt", "w");
        if (note) {
            fprintf(note, "beat %d\n", beat);
            fclose(note);
        }
        Sleep(1000);
    }
    return 42;
}