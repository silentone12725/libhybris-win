#!/usr/bin/env bash
# Reconstructed win_build4_diag.sh — build libdrm_client.dll (hybris core +
# DRM wrapper) and smoke2.exe on Windows x86-64 (MinGW-w64 UCRT64).
set -uo pipefail

REPO=/c/libhybris-win/hybris
Q="$REPO/common/q"
COMMON="$REPO/common"
INC="$REPO/include"
BIONIC_INC="$Q/bionic/libc/include"
BIONIC_PRIV="$Q/bionic/libc"
NS=/c/adam-src/native          # native DRM wrapper sources (and cJSON)
LOCAL_NS=/c/libhybris-win/recovery/drm-native
BUILD=/c/adam-build
STUB="$BUILD/stub"

rm -rf "$BUILD" && mkdir -p "$STUB/android-base" "$STUB/debuggerd" "$STUB/cutils"

# ── stub headers the CORE build needs (from build-and-test-x86_64.sh) ──
cat > "$STUB/android-config.h"  << 'EOF'
#pragma once
#define ANDROID_VERSION_MAJOR 10
#define ANDROID_VERSION_MINOR 0
#define ANDROID_VERSION_PATCH 0
EOF
cat > "$STUB/android-version.h" << 'EOF'
#pragma once
#define ANDROID_VERSION_MAJOR 10
EOF
cat > "$STUB/android-base/macros.h" << 'EOF'
#pragma once
#define DISALLOW_COPY_AND_ASSIGN(T) T(const T&) = delete; T& operator=(const T&) = delete
#define DISALLOW_IMPLICIT_CONSTRUCTORS(T) T() = delete; DISALLOW_COPY_AND_ASSIGN(T)
EOF
cat > "$STUB/config.h" << 'EOF'
#pragma once
#define PACKAGE_VERSION "0.1.0"
#define TRACE_DEBUG 0
EOF
cat > "$STUB/cutils/native_handle.h" << 'EOF'
#pragma once
#include <stdint.h>
typedef struct native_handle { int version; int numFds; int numInts; int data[0]; } native_handle_t;
native_handle_t* native_handle_create(int numFds, int numInts);
int native_handle_close(const native_handle_t* h);
int native_handle_delete(native_handle_t* h);
EOF
cat > "$STUB/debuggerd/handler.h" << 'EOF'
#pragma once
#include <stddef.h>
typedef struct { void *(*get_abort_message)(void); void (*post_dump)(void); } debuggerd_callbacks_t;
static inline void debuggerd_init(debuggerd_callbacks_t *cb) { (void)cb; }
EOF
# empty shims the NATIVE wrapper expects
: > "$STUB/win_posix.h"
: > "$STUB/win_signal.h"

export MSYS2_ARG_CONV_EXCL="-DDEFAULT_HYBRIS_LD_LIBRARY_PATH=*"

CORE_CFLAGS=(
  -fPIC -D__ANDROID__ -DANDROID -D_GNU_SOURCE -D_LARGEFILE64_SOURCE
  -DWANT_LINKER_Q -DANDROID_SMP=1 -D_USING_LIBCXX -DTRACE_DEBUG=0
  -DNO_RUNTIME_PROPERTY_CACHE -DLINKER_PLUGIN_DIR='"/tmp/hybris-linker"'
  -D__LP64__ -DDYNAMIC_LINKER -w
  "-I$INC" "-I$COMMON" "-I$Q" "-I$BIONIC_INC" "-I$BIONIC_PRIV" "-I$STUB"
)
NATIVE_CFLAGS=(
  -O2 -fPIC -DMyRelease -D_GNU_SOURCE -DDRM_LIB_BUILD -w
  "-I$LOCAL_NS" "-I$NS" "-I$INC" "-I$STUB"
)

OBJS=()
fail=0

cc_core() { # $1 src
  local o="$BUILD/core_$(basename "$1").o"
  echo "  CC(core) $(basename "$1")"
  if [[ "$1" == *.cpp ]]; then
    g++ -std=c++17 -include climits -c "${CORE_CFLAGS[@]}" -include "$COMMON/windows_core_compat.h" "$1" -o "$o"
  else
    gcc -std=gnu11 -c "${CORE_CFLAGS[@]}" -include "$COMMON/windows_core_compat.h" -x c "$1" -o "$o"
  fi
  if [[ $? -ne 0 ]]; then echo "  !! FAILED $1"; fail=1; else OBJS+=("$o"); fi
}
cc_native() { # $1 src
  local o="$BUILD/nat_$(basename "$1").o"
  echo "  CC(nat)  $(basename "$1")"
  if [[ "$1" == *.cpp ]]; then
    g++ -std=gnu++17 -c "${NATIVE_CFLAGS[@]}" "$1" -o "$o"
  else
    gcc -std=gnu11 -c "${NATIVE_CFLAGS[@]}" -include sys/time.h -x c "$1" -o "$o"
  fi
  if [[ $? -ne 0 ]]; then echo "  !! FAILED $1"; fail=1; else OBJS+=("$o"); fi
}
native_src() {
  if [[ -f "$LOCAL_NS/$1" ]]; then
    echo "$LOCAL_NS/$1"
  else
    echo "$NS/$1"
  fi
}

echo "=== CORE (hybris hooks + public API) ==="
for s in windows_core_hooks.c hooks_shm.c logging.c native_handle.c sysconf.c \
         windows_core_properties.c windows_hook_table.c dso_handle_counters.cpp; do
  cc_core "$COMMON/$s"
done
cc_core "$REPO/../recovery/guest_thread_bridge.cpp"

echo "=== NATIVE (DRM wrapper) ==="
for s in main.c cmdline.c hybris_stubs.c hybris_net.c drm_lib.c cJSON.c main.cpp guard.cpp; do
  cc_native "$(native_src "$s")"
done

if [[ $fail -ne 0 ]]; then echo "BUILD ABORTED (compile errors above)"; exit 1; fi

echo "=== Linking libdrm_client.dll ==="
g++ -shared -fPIC -o "$BUILD/libdrm_client.dll" "${OBJS[@]}" \
    -lsupc++ -lpthread -lm -lstdc++ -lws2_32 -ladvapi32 \
    -Wl,--export-all-symbols -Wl,--out-implib,"$BUILD/libdrm_client.dll.a"
if [[ $? -ne 0 ]]; then echo "LINK FAILED"; exit 1; fi
ls -lh "$BUILD/libdrm_client.dll"

echo "=== Building smoke2.exe ==="
gcc -std=gnu11 -O1 -g "-I$NS" /c/adam-src/smoke2.c "$BUILD/libdrm_client.dll" \
    -lpthread -lm -lws2_32 -ladvapi32 \
    -Xlinker --stack -Xlinker 0x4000000,0x4000000 \
    -o "$BUILD/smoke2.exe"
if [[ $? -ne 0 ]]; then echo "SMOKE2 LINK FAILED"; exit 1; fi
ls -lh "$BUILD/smoke2.exe"
echo "=== Building drm_lib_test.exe ==="
gcc -std=gnu11 -O1 -g "-I$LOCAL_NS" "$LOCAL_NS/drm_lib_test.c" "$BUILD/libdrm_client.dll" \
    -lpthread -lm -lws2_32 -ladvapi32 \
    -Xlinker --stack -Xlinker 0x4000000,0x4000000 \
    -o "$BUILD/drm_lib_test.exe"
if [[ $? -ne 0 ]]; then echo "DRM API TEST LINK FAILED"; exit 1; fi
ls -lh "$BUILD/drm_lib_test.exe"
echo "BUILD_OK"
