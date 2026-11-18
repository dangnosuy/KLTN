from __future__ import annotations

import re

API_SPECS = {
    "VirtualAlloc": "typedef LPVOID (WINAPI *pfn_VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);",
    "CreateThread": "typedef HANDLE (WINAPI *pfn_CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);",
    "WaitForSingleObject": "typedef DWORD (WINAPI *pfn_WaitForSingleObject_t)(HANDLE, DWORD);",
    "CloseHandle": "typedef BOOL (WINAPI *pfn_CloseHandle_t)(HANDLE);",
    "CreateFileMappingA": "typedef HANDLE (WINAPI *pfn_CreateFileMappingA_t)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);",
    "MapViewOfFile": "typedef LPVOID (WINAPI *pfn_MapViewOfFile_t)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);",
    "UnmapViewOfFile": "typedef BOOL (WINAPI *pfn_UnmapViewOfFile_t)(LPCVOID);",
    "Sleep": "typedef VOID (WINAPI *pfn_Sleep_t)(DWORD);",
    "IsDebuggerPresent": "typedef BOOL (WINAPI *pfn_IsDebuggerPresent_t)(VOID);",
}


def to_stack_chars(s: str) -> str:
    chars = [f"'{c}'" for c in s] + ["0"]
    return "{" + ", ".join(chars) + "}"


def transform_dynamic_api(code: str, seed: int = 0) -> str:
    """Resolve monitored Win32 APIs dynamically via LoadLibraryA and GetProcAddress."""
    if "/* NATIVE_DYNAMIC_API_RESOLVED */" in code:
        return code

    needed = []
    working_code = code
    for api, tdef in API_SPECS.items():
        if re.search(rf"\b{api}\b\s*\(", working_code):
            needed.append((api, tdef))
            working_code = re.sub(rf"\b{api}\b\s*\(", f"pfn_{api}(", working_code)

    if not needed:
        return code

    typedef_block = "\n".join(tdef for _, tdef in needed)
    setup_lines = [
        "    /* NATIVE_DYNAMIC_API_RESOLVED */",
        f"    char s_k32[] = {to_stack_chars('kernel32.dll')};",
        "    HMODULE h_k32 = LoadLibraryA(s_k32);",
        "    if (!h_k32) return 1;",
    ]
    for api, _ in needed:
        setup_lines.extend([
            f"    char s_{api}[] = {to_stack_chars(api)};",
            f"    pfn_{api}_t pfn_{api} = (pfn_{api}_t)GetProcAddress(h_k32, s_{api});",
            f"    if (!pfn_{api}) return 1;",
        ])
    setup_block = "\n".join(setup_lines) + "\n"

    main_match = re.search(r"int\s+main\s*\([^)]*\)\s*\{", working_code)
    if not main_match:
        return code

    idx_brace = main_match.end()
    return (
        working_code[: main_match.start()]
        + typedef_block
        + "\n\n"
        + working_code[main_match.start() : idx_brace]
        + "\n"
        + setup_block
        + working_code[idx_brace:]
    )


def transform_benign_workload(code: str, seed: int = 0) -> str:
    """Inject a small, pure-math benign computation function executed before payload."""
    if "/* NATIVE_BENIGN_WORKLOAD */" in code:
        return code

    variant = seed % 4
    func_name = f"_native_workload_{abs(seed) % 10000}"

    if variant == 0:
        func_def = f"""
static void {func_name}(void) {{
    /* NATIVE_BENIGN_WORKLOAD */
    volatile int a[4] = {{1, 2, 3, 4}};
    volatile int b[4] = {{5, 6, 7, 8}};
    volatile int c[4] = {{0}};
    for (int i = 0; i < 2; i++) {{
        for (int j = 0; j < 2; j++) {{
            for (int k = 0; k < 2; k++) {{
                c[i * 2 + j] += a[i * 2 + k] * b[k * 2 + j];
            }}
        }}
    }}
}}
"""
    elif variant == 1:
        func_def = f"""
static void {func_name}(void) {{
    /* NATIVE_BENIGN_WORKLOAD */
    volatile int coeffs[5] = {{3, -2, 5, -1, 7}};
    volatile int x = 3;
    volatile int res = 0;
    for (int i = 0; i < 5; i++) {{
        res = res * x + coeffs[i];
    }}
}}
"""
    elif variant == 2:
        func_def = f"""
static void {func_name}(void) {{
    /* NATIVE_BENIGN_WORKLOAD */
    volatile unsigned int buf[8] = {{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}};
    volatile unsigned int sum = 0;
    for (int i = 0; i < 8; i++) {{
        sum = (sum << 3) ^ (buf[i] + (i * 17));
    }}
}}
"""
    else:
        func_def = f"""
static void {func_name}(void) {{
    /* NATIVE_BENIGN_WORKLOAD */
    volatile int arr[8] = {{12, 3, 7, 1, 9, 14, 5, 2}};
    for (int i = 0; i < 7; i++) {{
        for (int j = 0; j < 7 - i; j++) {{
            if (arr[j] > arr[j + 1]) {{
                int tmp = arr[j];
                arr[j] = arr[j + 1];
                arr[j + 1] = tmp;
            }}
        }}
    }}
}}
"""

    main_match = re.search(r"int\s+main\s*\([^)]*\)\s*\{", code)
    if not main_match:
        return code

    idx_brace = main_match.end()
    call_line = f"\n    {func_name}();\n"
    return (
        code[: main_match.start()]
        + func_def.strip()
        + "\n\n"
        + code[main_match.start() : idx_brace]
        + call_line
        + code[idx_brace:]
    )


def transform_benign_iat(code: str, seed: int = 0) -> str:
    """Inject legitimate benign Win32 API calls to balance the Import Address Table."""
    if "/* NATIVE_BENIGN_IAT */" in code:
        return code

    main_match = re.search(r"int\s+main\s*\([^)]*\)\s*\{", code)
    if not main_match:
        return code

    idx_brace = main_match.end()
    iat_block = """
    /* NATIVE_BENIGN_IAT */
    SYSTEM_INFO _native_si;
    GetSystemInfo(&_native_si);
    volatile DWORD _native_page_size = _native_si.dwPageSize;
    (void)_native_page_size;
"""
    return code[:idx_brace] + iat_block + code[idx_brace:]


def transform_stack_strings(code: str, seed: int = 0) -> str:
    """Convert raw string literals outside of preprocessor lines to stack character arrays."""
    lines = code.splitlines(keepends=True)
    out_lines = []
    str_counter = 0

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#include") or stripped.startswith("#pragma"):
            out_lines.append(line)
            continue

        def replace_str(match):
            nonlocal str_counter
            lit = match.group(1)
            # Only convert strings of length >= 2
            if len(lit) < 2:
                return match.group(0)
            str_counter += 1
            var_name = f"_s_{str_counter}_{abs(seed) % 1000}"
            # Return stack init if it's in a declaration context or replace with stack array
            return f"(char[]){to_stack_chars(lit)}"

        new_line = re.sub(r'"([^"\\]*(?:\\.[^"\\]*)*)"', replace_str, line)
        out_lines.append(new_line)

    return "".join(out_lines)


def transform_opaque_predicate(code: str, seed: int = 0) -> str:
    """Wrap execution logic in an invariant condition to diversify CFG without bloat."""
    if "/* NATIVE_OPAQUE_PREDICATE */" in code:
        return code

    main_match = re.search(r"int\s+main\s*\([^)]*\)\s*\{", code)
    if not main_match:
        return code

    idx_brace = main_match.end()
    block = """
    /* NATIVE_OPAQUE_PREDICATE */
    volatile int _native_cond = (sizeof(void*) >= 4);
    if (!_native_cond) return 0;
"""
    return code[:idx_brace] + block + code[idx_brace:]


def transform_variable_renaming(code: str, seed: int = 0) -> str:
    """Rename suspicious variable names (exec, th, hMap) to benign names."""
    if "/* NATIVE_VARS_RENAMED */" in code:
        return code

    working = code
    renames = {
        r"\bexec\b": f"_p_buffer_{abs(seed) % 1000}",
        r"\bth\b": f"_h_worker_{abs(seed) % 1000}",
        r"\bhMap\b": f"_h_storage_{abs(seed) % 1000}",
        r"\bbase\b": f"_p_memory_{abs(seed) % 1000}",
    }
    for pat, rep in renames.items():
        working = re.sub(pat, rep, working)

    main_match = re.search(r"int\s+main\s*\([^)]*\)\s*\{", working)
    if not main_match:
        return code

    idx_brace = main_match.end()
    marker = "\n    /* NATIVE_VARS_RENAMED */\n"
    return working[:idx_brace] + marker + working[idx_brace:]


def transform_clean_strip(code: str, seed: int = 0) -> str:
    """Standardize source formatting, ensure windows.h header is present."""
    working = code
    if "#include <windows.h>" not in working:
        working = "#include <windows.h>\n" + working
    # Strip multi-line comments except NATIVE markers
    working = re.sub(r"/\*(?!\s*NATIVE_).*?\*/", "", working, flags=re.DOTALL)
    # Strip line comments except our markers
    clean_lines = []
    for line in working.splitlines(keepends=True):
        if line.strip().startswith("//") and "NATIVE_" not in line:
            continue
        clean_lines.append(line)
    return "".join(clean_lines)


MUTATORS = {
    "dynamic_api": transform_dynamic_api,
    "benign_workload": transform_benign_workload,
    "benign_iat": transform_benign_iat,
    "stack_strings": transform_stack_strings,
    "opaque_predicate": transform_opaque_predicate,
    "variable_renaming": transform_variable_renaming,
    "clean_strip": transform_clean_strip,
}
