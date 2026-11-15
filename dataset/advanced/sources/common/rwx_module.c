#include <windows.h>

__attribute__((section(".rwx_sec"), used))
unsigned char vulnerable_shared_space[4096] = { 0x90 };

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return TRUE;
}
