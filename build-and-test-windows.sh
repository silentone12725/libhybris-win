#!/usr/bin/env bash
# Build and run the Windows-native portability layer tests under MSYS2/UCRT64.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
Q="$ROOT/hybris/common/q"
BUILD="${TMPDIR:-/tmp}/libhybris-win-native"
ROOTFS="${HYBRIS_ROOTFS:-}"

if [[ -z "$ROOTFS" ]]; then
    echo "HYBRIS_ROOTFS must point to an Android x86-64 rootfs" >&2
    exit 2
fi

rm -rf "$BUILD"
mkdir -p "$BUILD"

cc -std=c11 -Wall -Wextra -Werror -D_WIN32 -I"$Q" \
    -c "$Q/windows_elf_host.c" -o "$BUILD/windows_elf_host.o"
cc -std=c11 -Wall -Wextra -Werror -D_WIN32 -I"$Q" \
    -c "$Q/windows_elf_reader.c" -o "$BUILD/windows_elf_reader.o"
g++ -std=c++17 -Wall -Wextra -Werror -D_WIN32 -I"$Q" \
    -c "$Q/windows_tls_backend.cpp" -o "$BUILD/windows_tls_backend.o"

cc -std=c11 -Wall -Wextra -Werror -pedantic -I"$Q" \
    "$Q/x86_64_relocation.c" "$Q/x86_64_relocation_test.c" \
    -o "$BUILD/x86_64_relocation_test.exe"
g++ -std=c++17 -Wall -Wextra -Werror -pedantic -D_WIN32 -I"$Q" \
    "$Q/windows_tls_backend.cpp" "$Q/windows_tls_backend_test.cpp" \
    -o "$BUILD/windows_tls_backend_test.exe"
cc -std=c11 -Wall -Wextra -Werror -D_WIN32 -I"$Q" \
    "$Q/windows_elf_host.c" "$Q/windows_elf_reader.c" \
    "$Q/windows_elf_reader_test.c" -o "$BUILD/windows_elf_reader_test.exe"

"$BUILD/x86_64_relocation_test.exe"
"$BUILD/windows_tls_backend_test.exe"
"$BUILD/windows_elf_reader_test.exe" "$ROOTFS/system/lib64/libc.so"
