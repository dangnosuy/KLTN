// SAMPLE: g2_02 | DLL Search Order Hijacking | Group: Execution Hijacking
//
// injector.c — Main EXE that demonstrates DLL search order hijacking.
//   1. Creates C:\C1_Sandbox\hijack_cwd\ directory.
//   2. Copies evil_version2.dll (compiled from evil.c) into that directory.
//   3. Sets CWD to C:\C1_Sandbox\hijack_cwd\.
//   4. Calls LoadLibraryA("evil_version2.dll") with a relative name —
//      Windows searches CWD first, loads our planted DLL.
//   5. DllMain of evil.c (the hijacked path) writes the C1 proof.
//
// Compile: x86_64-w64-mingw32-gcc -o injector.exe injector.c
// Compile DLL first: x86_64-w64-mingw32-gcc -shared -o evil_version2.dll evil.c
//
// NOTE: Copy evil_version2.dll next to injector.exe before running,
//       or place it in the same build directory. The injector copies it
//       into the hijack CWD at runtime.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HIJACK_DIR  "C:\\C1_Sandbox\\hijack_cwd\\"
#define DLL_NAME    "evil_version2.dll"

int main(void) {
    /* ---- Step 1: Ensure the sandbox and hijack CWD exist ---- */
    if (!CreateDirectoryA("C:\\C1_Sandbox", NULL) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        fprintf(stderr, "[injector] CreateDirectory C:\\C1_Sandbox failed: %lu\n",
                GetLastError());
        return EXIT_FAILURE;
    }
    if (!CreateDirectoryA(HIJACK_DIR, NULL) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        fprintf(stderr, "[injector] CreateDirectory %s failed: %lu\n",
                HIJACK_DIR, GetLastError());
        return EXIT_FAILURE;
    }

    /* ---- Step 2: Locate the DLL next to this executable ---- */
    char selfDir[MAX_PATH];
    GetModuleFileNameA(NULL, selfDir, MAX_PATH);
    /* Trim filename portion */
    char *last_sep = strrchr(selfDir, '\\');
    if (last_sep) *(last_sep + 1) = '\0';

    char srcDll[MAX_PATH];
    snprintf(srcDll, sizeof(srcDll), "%s%s", selfDir, DLL_NAME);

    char dstDll[MAX_PATH];
    snprintf(dstDll, sizeof(dstDll), "%s%s", HIJACK_DIR, DLL_NAME);

    /* Copy evil_version2.dll into the hijack CWD */
    if (!CopyFileA(srcDll, dstDll, FALSE)) {
        fprintf(stderr, "[injector] CopyFile %s -> %s failed: %lu\n",
                srcDll, dstDll, GetLastError());
        fprintf(stderr, "[injector] Make sure evil_version2.dll is compiled and "
                        "placed next to injector.exe\n");
        return EXIT_FAILURE;
    }
    printf("[injector] Planted DLL at: %s\n", dstDll);

    /* ---- Step 3: Set CWD to the hijack directory ---- */
    if (!SetCurrentDirectoryA(HIJACK_DIR)) {
        fprintf(stderr, "[injector] SetCurrentDirectory failed: %lu\n",
                GetLastError());
        return EXIT_FAILURE;
    }
    printf("[injector] CWD set to: %s\n", HIJACK_DIR);

    /* ---- Step 4: LoadLibrary with relative name — CWD is searched first ----
     * Windows DLL search order (default, SafeDllSearchMode=1):
     *   1. The directory the application loaded from
     *   2. The system directory
     *   3. The 16-bit system directory
     *   4. The Windows directory
     *   5. The CWD  <-- our evil DLL lives here
     *   6. PATH directories
     *
     * Because evil_version2.dll is NOT a known system DLL, the loader walks
     * the list and finds it in CWD (step 5).  DllMain runs → proof written.
     */
    printf("[injector] Loading '%s' (relative) — DLL search will hit CWD...\n",
           DLL_NAME);
    HMODULE hMod = LoadLibraryA(DLL_NAME);
    if (!hMod) {
        fprintf(stderr, "[injector] LoadLibraryA failed: %lu\n", GetLastError());
        return EXIT_FAILURE;
    }
    printf("[injector] LoadLibraryA succeeded — evil DLL loaded (proof written by DllMain).\n");

    /* Cleanup */
    FreeLibrary(hMod);
    /* Optionally remove planted DLL */
    DeleteFileA(dstDll);

    return EXIT_SUCCESS;
}
