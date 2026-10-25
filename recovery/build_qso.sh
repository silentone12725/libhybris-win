#!/usr/bin/env bash
# Rebuild ONLY q.so (linker plugin) — mirrors step 1 of build-and-test-x86_64.sh.
set -uo pipefail
REPO=/c/libhybris-win/hybris
Q="$REPO/common/q"; COMMON="$REPO/common"; INC="$REPO/include"
BIONIC_INC="$Q/bionic/libc/include"; BIONIC_PRIV="$Q/bionic/libc"
BUILD=/tmp/hybris-x86_64-build
rm -rf "$BUILD" && mkdir -p "$BUILD/stub/android-base" "$BUILD/stub/debuggerd" "$BUILD/stub/cutils"
cat > "$BUILD/stub/android-config.h"  << 'EOF'
#pragma once
#define ANDROID_VERSION_MAJOR 10
#define ANDROID_VERSION_MINOR 0
#define ANDROID_VERSION_PATCH 0
EOF
cat > "$BUILD/stub/android-version.h" << 'EOF'
#pragma once
#define ANDROID_VERSION_MAJOR 10
EOF
cat > "$BUILD/stub/android-base/macros.h" << 'EOF'
#pragma once
#define DISALLOW_COPY_AND_ASSIGN(T) T(const T&) = delete; T& operator=(const T&) = delete
#define DISALLOW_IMPLICIT_CONSTRUCTORS(T) T() = delete; DISALLOW_COPY_AND_ASSIGN(T)
EOF
cat > "$BUILD/stub/config.h" << 'EOF'
#pragma once
#define PACKAGE_VERSION "0.1.0"
#define TRACE_DEBUG 0
EOF
cat > "$BUILD/stub/cutils/native_handle.h" << 'EOF'
#pragma once
#include <stdint.h>
typedef struct native_handle { int version; int numFds; int numInts; int data[0]; } native_handle_t;
native_handle_t* native_handle_create(int numFds, int numInts);
int native_handle_close(const native_handle_t* h);
int native_handle_delete(native_handle_t* h);
EOF
cat > "$BUILD/stub/debuggerd/handler.h" << 'EOF'
#pragma once
#include <stddef.h>
typedef struct { void *(*get_abort_message)(void); void (*post_dump)(void); } debuggerd_callbacks_t;
static inline void debuggerd_init(debuggerd_callbacks_t *cb) { (void)cb; }
EOF
export MSYS2_ARG_CONV_EXCL="-DDEFAULT_HYBRIS_LD_LIBRARY_PATH=*"
CF=( -std=c++17 -fPIC -D__ANDROID__ -DANDROID -D_GNU_SOURCE -D_LARGEFILE64_SOURCE
  -DWANT_LINKER_Q -DANDROID_SMP=1 -D_USING_LIBCXX -DTRACE_DEBUG=0
  -DNO_RUNTIME_PROPERTY_CACHE -DLINKER_PLUGIN_DIR='"/tmp/hybris-linker"'
  -D__LP64__ -DDYNAMIC_LINKER -w
  "-I$INC" "-I$COMMON" "-I$Q" "-I$BIONIC_INC" "-I$BIONIC_PRIV" "-I$BUILD/stub" )
Q_SRCS=(
  "$Q/hybris_compat.cpp" "$Q/bionic/libc/bionic/bionic_call_ifunc_resolver.cpp"
  "$Q/dlfcn.cpp" "$Q/linker_allocator.cpp" "$Q/linker_block_allocator.cpp"
  "$Q/linker.cpp" "$Q/linker_cfi.cpp" "$Q/linker_config.cpp" "$Q/linker_dlwarning.cpp"
  "$Q/linker_gdb_support.cpp" "$Q/linker_globals.cpp" "$Q/linker_logger.cpp"
  "$Q/linker_main.cpp" "$Q/linker_mapped_file_fragment.cpp" "$Q/linker_memory.cpp"
  "$Q/linker_namespaces.cpp" "$Q/linker_phdr.cpp" "$Q/linker_sdk_versions.cpp"
  "$Q/linker_soinfo.cpp" "$Q/linker_tls.cpp" "$Q/windows_tls_backend.cpp"
  "$Q/x86_64_guest_tls_rewriter.cpp" "$Q/linker_utils.cpp" "$Q/rt.cpp"
  "$Q/bionic/libc/bionic/bionic_elf_tls.cpp" "$Q/bionic/libc/bionic/bionic_allocator.cpp"
  "$Q/x86_64_relocation.c" "$COMMON/abi_thunks.c" "$COMMON/strlcpy.c" "$COMMON/strlcat.c"
  "$Q/windows_elf_host.c" "$Q/windows_elf_reader.c" )
OBJS=(); fail=0
for s in "${Q_SRCS[@]}"; do
  o="$BUILD/$(echo "$s"|md5sum|cut -c1-8)_$(basename "$s").o"
  echo "  CC $(basename "$s")"
  if [[ "$s" == *.c ]]; then
    gcc -c "${CF[@]/-std=c++17/-std=gnu11}" -x c "$s" -o "$o" || fail=1
  else
    g++ -c "${CF[@]}" -include climits "$s" -o "$o" || fail=1
  fi
  OBJS+=("$o")
done
[[ $fail -ne 0 ]] && { echo "Q COMPILE FAILED"; exit 1; }
echo "=== Linking q.so ==="
g++ -shared -fPIC -o "$BUILD/q.so" "${OBJS[@]}" -lsupc++ || { echo LINK FAIL; exit 1; }
cp "$BUILD/q.so" /c/storage/hybris-linker/q.so
ls -lh /c/storage/hybris-linker/q.so
echo QSO_OK
