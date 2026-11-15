#include <windows.h>
#include <string.h>
int main(void) {
    char path[MAX_PATH];
    DWORD size = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (!size || size >= MAX_PATH) return 1;
    char *name = strrchr(path, '\\');
    if (!name || (size_t)(name - path) + sizeof("\\fixture.dll") > sizeof(path)) return 1;
    strcpy(name, "\\fixture.dll");
    HMODULE library = LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library) return 1;
    typedef int (*fixture_function)(void);
    fixture_function run = (fixture_function)GetProcAddress(library, "fixture_run");
    int code = run ? run() : 1;
    FreeLibrary(library);
    return code;
}
