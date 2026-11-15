#include <windows.h>
#include "../common/fixture.h"
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--child") == 0) return write_fixture();
    char executable[MAX_PATH], command[MAX_PATH + 32];
    DWORD size = GetModuleFileNameA(NULL, executable, MAX_PATH);
    if (!size || size >= MAX_PATH) return 1;
    if (snprintf(command, sizeof(command), "\"%s\" --child", executable) < 0) return 1;
    STARTUPINFOA startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    if (!CreateProcessA(executable, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) return 1;
    DWORD exit_code = 1;
    if (WaitForSingleObject(process.hProcess, 10000) != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 5000);
    } else if (!GetExitCodeProcess(process.hProcess, &exit_code)) exit_code = 1;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return exit_code == 0 ? 0 : 1;
}
