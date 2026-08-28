#include <string.h>
#include <windows.h>

/* Blind-eval fixture: a native Win32 DLL with an exported check function. */
__declspec(dllexport) int __cdecl check_token(const char *token)
{
    return strcmp(token, "minusone-dll-proof-9c4e") == 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)hinstDLL; (void)fdwReason; (void)lpvReserved;
    return 1;
}
