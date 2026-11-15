#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$root_dir/sources"
output_dir="$root_dir/build"
compiler="${MINGW_CC:-x86_64-w64-mingw32-gcc}"
assembler="${MINGW_AS:-x86_64-w64-mingw32-as}"
objcopy="${MINGW_OBJCOPY:-x86_64-w64-mingw32-objcopy}"
objdump="${MINGW_OBJDUMP:-x86_64-w64-mingw32-objdump}"

command -v "$compiler" >/dev/null
command -v "$assembler" >/dev/null
command -v "$objcopy" >/dev/null
command -v "$objdump" >/dev/null
command -v xxd >/dev/null

# Preserve the manifest; every executable and DLL is rebuilt from source.
rm -f "$output_dir"/*.exe "$output_dir"/*.dll
mkdir -p "$output_dir"

echo "[build] payload.dll"
"$compiler" -shared -nostdlib -Wl,--entry,DllMain -Wl,--subsystem,windows \
    "$source_dir/common/payload_dll.c" -lkernel32 -o "$output_dir/payload.dll"

echo "[build] embedded_dll.h"
xxd -i -n embedded_dll "$output_dir/payload.dll" > "$source_dir/common/embedded_dll.h"

echo "[build] syscall_stubs.o"
"$assembler" "$source_dir/common/syscall_stubs.s" -o "$output_dir/syscall_stubs.o"

echo "[build] rwx_module.dll"
"$compiler" -shared "$source_dir/common/rwx_module.c" -o "$output_dir/rwx_module.dll"
"$objcopy" --set-section-flags .rwx_sec=alloc,load,code,data,contents "$output_dir/rwx_module.dll"
if ! "$objdump" -h "$output_dir/rwx_module.dll" | grep -A1 ' .rwx_sec ' | grep -q 'CODE.*DATA'; then
    echo "[build] rwx_module.dll does not contain an RWX .rwx_sec section" >&2
    exit 1
fi

while IFS= read -r source; do
    name="$(basename "${source%.c}")"
    args=("$compiler" "$source")
    if [[ "$name" == "mockingjay" ]]; then
        args+=(-lpsapi)
    fi
    if [[ "$name" == "hells_gate" || "$name" == "indirect_syscall" ]]; then
        args+=("$output_dir/syscall_stubs.o")
    fi
    args+=(-o "$output_dir/$name.exe")
    echo "[build] $name.exe"
    "${args[@]}"
done < <(find "$source_dir/baseline" "$source_dir/resolution" "$source_dir/injection" "$source_dir/experimental" -maxdepth 1 -name '*.c' -type f | sort)

rm -f "$output_dir/syscall_stubs.o"
echo "[build] complete: $(find "$output_dir" -maxdepth 1 -type f \( -name '*.exe' -o -name '*.dll' \) | wc -l) artifacts"
