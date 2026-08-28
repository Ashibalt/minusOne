/**
 * Self-dumping minidump fixture for the cdb postmortem live test. Links
 * against dbghelp and writes a MiniDumpNormal snapshot of itself to argv[1].
 * No SeDebugPrivilege is needed (the process dumps itself), so this runs
 * unprivileged on the analyst host. Compile: gcc -O2 -o selfdump.exe
 * selfdump.c -ldbghelp
 */
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

int main(int argc, char** argv) {
  if (argc < 2) {
    printf("usage: selfdump <out.dmp>\n");
    return 3;
  }
  HANDLE h = CreateFileA(argv[1], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (h == INVALID_HANDLE_VALUE) {
    printf("create err %lu\n", GetLastError());
    return 1;
  }
  BOOL ok = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), h, MiniDumpNormal, NULL, NULL, NULL);
  CloseHandle(h);
  printf("dump %s\n", ok ? "ok" : "fail");
  return ok ? 0 : 2;
}
