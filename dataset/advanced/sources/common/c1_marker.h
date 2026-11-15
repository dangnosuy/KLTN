#ifndef C1_MARKER_H
#define C1_MARKER_H

#include <windows.h>

#define C1_MARKER_PATH "c1_pass.txt"

static void c1_reset_marker(void) {
    DeleteFileA(C1_MARKER_PATH);
    DeleteFileA("canary_ipconfig.txt");
}

static BOOL c1_write_marker(void) {
    STARTUPINFOA startup = { sizeof(startup) };
    PROCESS_INFORMATION process = { 0 };
    char command[] = "cmd.exe /d /c ipconfig /all > canary_ipconfig.txt";
    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &startup, &process)) {
        return FALSE;
    }
    DWORD wait = WaitForSingleObject(process.hProcess, 10000);
    DWORD exit_code = 1;
    BOOL exited = wait == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    if (!exited || exit_code != 0) return FALSE;

    static const char marker[] = "ALIVE\n";
    DWORD written = 0;
    HANDLE file = CreateFileA(
        C1_MARKER_PATH,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    BOOL ok = WriteFile(file, marker, sizeof(marker) - 1, &written, NULL);
    CloseHandle(file);
    return ok && written == sizeof(marker) - 1;
}

static BOOL c1_marker_passed(void) {
    char value[8] = { 0 };
    DWORD read = 0;
    HANDLE file = CreateFileA(
        C1_MARKER_PATH,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (file == INVALID_HANDLE_VALUE) return FALSE;
    BOOL ok = ReadFile(file, value, sizeof(value) - 1, &read, NULL);
    CloseHandle(file);
    return ok && read >= 5 && value[0] == 'A' && value[1] == 'L' && value[2] == 'I' &&
        value[3] == 'V' && value[4] == 'E';
}

#endif
