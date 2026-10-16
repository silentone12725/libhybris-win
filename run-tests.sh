#!/usr/bin/env bash
# Build and run libhybris q-linker unit tests on x86-64 glibc host.
# No autotools, no android-headers package required — uses headers from repo.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
Q="$ROOT/hybris/common/q"
STUB_INC="/tmp/hybris-test-inc"
BUILD="/tmp/hybris-test-bins"
mkdir -p "$STUB_INC/android-base" "$BUILD"

# Stub for android-base/macros.h (block_allocator dep)
cat > "$STUB_INC/android-base/macros.h" << 'EOF'
#pragma once
#define DISALLOW_COPY_AND_ASSIGN(T) T(const T&) = delete; T& operator=(const T&) = delete
#define DISALLOW_IMPLICIT_CONSTRUCTORS(T) T() = delete; DISALLOW_COPY_AND_ASSIGN(T)
EOF

GTEST_FLAGS="$(pkg-config --cflags gtest)"
GTEST_LIBS="$(pkg-config --libs gtest) -lgtest_main"

compile() {
    g++ -std=c++17 \
        "-I$Q" "-I$Q/bionic/libc/include" "-I$Q/bionic/libc" "-I$STUB_INC" \
        -include climits \
        $GTEST_FLAGS "$@" $GTEST_LIBS
}

compile_c() {
    cc -std=c11 -Wall -Wextra -Werror -pedantic \
        "-I$Q" "-I$ROOT/hybris/include" "$@"
}

echo "=== building linked_list_test ==="
compile "$Q/linked_list_test.cpp" -o "$BUILD/test_linked_list"

echo "=== building linker_utils_test ==="
cc -std=c11 -I"$ROOT/hybris/common" -c "$ROOT/hybris/common/strlcpy.c" \
    -o "$BUILD/strlcpy.o"
compile "$Q/linker_utils.cpp" "$Q/linker_utils_test.cpp" "$Q/linker_test_globals.cpp" \
    "$BUILD/strlcpy.o" \
    -o "$BUILD/test_linker_utils"

echo "=== building linker_block_allocator_test ==="
compile "$Q/linker_block_allocator.cpp" "$Q/linker_block_allocator_test.cpp" "$Q/linker_test_globals.cpp" \
    -o "$BUILD/test_block_alloc"

echo "=== building linker_sleb128_test ==="
compile "$Q/linker_sleb128_test.cpp" "$Q/linker_test_globals.cpp" \
    -o "$BUILD/test_sleb128"

echo "=== building x86_64_relocation_test ==="
compile_c "$Q/x86_64_relocation.c" "$Q/x86_64_relocation_test.c" \
    -o "$BUILD/test_x86_64_relocation"

echo "=== building windows_tls_backend_test ==="
g++ -std=c++17 -Wall -Wextra -Werror -pedantic -pthread \
    "-I$Q" "$Q/windows_tls_backend.cpp" "$Q/windows_tls_backend_test.cpp" \
    -o "$BUILD/test_windows_tls_backend"

echo "=== building abi_thunks_test ==="
compile_c "$ROOT/hybris/common/abi_thunks.c" "$ROOT/hybris/tests/test_abi_thunks.c" \
    -lm -o "$BUILD/test_abi_thunks"

echo "=== building bionic_compat_test ==="
compile "$Q/bionic_compat_test.cpp" -pthread \
    -o "$BUILD/test_bionic_compat"

echo ""
PASS=0; FAIL=0
for bin in "$BUILD"/test_*; do
    echo ">>> $(basename $bin)"
    if "$bin" 2>&1; then
        PASS=$((PASS+1))
    else
        FAIL=$((FAIL+1))
    fi
    echo ""
done

echo "=== RESULT: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
