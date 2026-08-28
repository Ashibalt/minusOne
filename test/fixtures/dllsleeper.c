/* Trusted DLL dynamic-plane fixture: an export that drops a marker file and
 * sleeps, so the host process stays alive long enough for pe-sieve to dump it.
 * DllMain stays minimal. Never use untrusted samples for pipeline verification.
 */
#include <windows.h>
#include <stdio.h>

__declspec(dllexport) void __cdecl RunPayload(void) {
    FILE *note = fopen("dll-dropped-note.txt", "w");
    if (note) {
        fputs("minusone-dll-proof", note);
        fclose(note);
    }
    Sleep(20000);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
