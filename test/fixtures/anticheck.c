#include <stdio.h>
#include <windows.h>

/* Anti-debug probe: reports the observable debug state exactly the way
 * packers do — PEB.BeingDebugged, NtGlobalFlag, heap flags. Under a plain
 * gdb run BeingDebugged is 1; with the minusOne harden layer it must read 0. */
int main(void) {
#ifdef _WIN64
    unsigned char *peb = (unsigned char *)__readgsqword(0x60);
#else
    unsigned char *peb = (unsigned char *)__readfsdword(0x30);
#endif
    unsigned int ngf = *(unsigned int *)(peb + 0xBC);
    printf("BeingDebugged=%d\n", peb[2]);
    printf("NtGlobalFlag=0x%x\n", ngf);
    if (peb[2] != 0) {
        printf("VERDICT=debugged\n");
        return 1;
    }
    printf("VERDICT=clean\n");
    return 0;
}
