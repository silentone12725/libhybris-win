# Build and test

## Reproducible Linux baseline

The project pins the Linux validation image in `Dockerfile` and records tool
versions in `.tool-versions`. The offline test command after image creation is:

```bash
make test
```

Equivalent clean-room commands are:

```bash
docker build --tag libhybris-win:test .
docker run --rm --network none libhybris-win:test
```

`make test` runs the host regression suite and creates the deterministic
`.build/minimal-x86_64.so` fixture. It does not download an Android rootfs.

## Linux Q/core smoke

With an x86-64 Android rootfs whose `lib64` directory contains the Android
system libraries:

```bash
HYBRIS_ROOTFS=/path/to/system/lib64 \
HYBRIS_SMOKE_LIBRARY=/path/to/system/lib64/libm.so \
HYBRIS_SMOKE_SYMBOL=cos \
HYBRIS_SMOKE_OPERATION=cos \
./build-and-test-x86_64.sh
```

## Emulator rootfs preparation

For the configured emulator:

```bash
adb -s emulator-5554 root
mkdir -p /tmp/android-x86_64-rootfs/system
adb -s emulator-5554 pull /system/lib64 /tmp/android-x86_64-rootfs/system/
adb -s emulator-5554 pull /system/bin/linker64 /tmp/android-x86_64-rootfs/system/bin/
```

The Linux real-library smoke used an Android x86-64 emulator rootfs and loaded
`libm.so`, resolving and executing `cos(0)`. For the emulator's `libz.so`, use
the same command with `HYBRIS_SMOKE_LIBRARY=.../libz.so`,
`HYBRIS_SMOKE_SYMBOL=crc32`, and `HYBRIS_SMOKE_OPERATION=crc32` to execute a
representative checksum operation.

## Native Windows

Use an MSYS2 UCRT64 shell with GCC/G++, Bash, and the Android NDK x86-64
Clang toolchain:

```bash
export PATH=/ucrt64/bin:/usr/bin:$PATH
export ANDROID_NDK_ROOT=/c/path/to/android-ndk-r26d
HYBRIS_ROOTFS=/c/path/to/android/rootfs ./build-and-test-windows.sh
./build-and-test-x86_64.sh
```

The native Windows Q runtime fixture is built with the NDK and executes a
dependency, constructor, IFUNC, TLS, symbol lookup, and close flow. The core
wrapper smoke defaults to that fixture because the current Windows guest TLS
backend is dynamic/FLS-backed. The Windows mapping path still reads the real
rootfs `system/lib64/libc.so`.

The Q fixture host also checks `dladdr`, the missing-symbol failure behavior of
`dlvsym`, and `dl_iterate_phdr` enumeration. These checks cover the Q linker
exports directly; they do not imply complete Android symbol-version policy.

The same Windows Q build also compiles NDK global-dynamic and local-dynamic
TLS fixtures. The TLS model host loads both modules, checks initialization and
read/write behavior, and verifies independent values on a second native
Windows thread before unloading them.

To deliberately exercise the currently unsupported real-Android initial-image
TLS path:

```bash
HYBRIS_WINDOWS_CORE_SMOKE_REAL_ANDROID=1 \
HYBRIS_ROOTFS=/c/path/to/android/rootfs/system/lib64 \
./build-and-test-x86_64.sh
```

This command is expected to fail until guest static/IE TLS access is implemented.

## Evidence policy

Every report must name the platform, commit, command, and result. A successful
ELF parse is not evidence of successful execution, and symbol resolution alone
is not evidence of complete library compatibility.
