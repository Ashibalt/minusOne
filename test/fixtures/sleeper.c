/* Trusted dynamic-plane fixture: sleeps, prints markers, drops a file.
 * Never use untrusted samples for pipeline verification — this one is ours. */
#include <stdio.h>
#include <windows.h>

int main(void) {
  FILE *note = fopen("dropped-note.txt", "w");
  if (note) {
    fputs("minusone-dynamic-proof", note);
    fclose(note);
  }
  printf("sleeper-started\n");
  fflush(stdout);
  Sleep(20000);
  printf("sleeper-done\n");
  fflush(stdout);
  return 42;
}
