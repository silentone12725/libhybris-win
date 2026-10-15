# libhybris-win

`libhybris-win` is an experimental, unofficial Windows x64 port of the Q ELF
loader from [libhybris](https://github.com/libhybris/libhybris). It is intended
to explore loading Android x86-64 ELF shared libraries inside a native Windows
process, without asking the Windows PE loader to load those ELF modules.

This repository is a portability fork and is not an official Windows release
of libhybris. The source retains the upstream licenses, notices, and
attribution; see the `LICENSE.*` files and `hybris/AUTHORS` for the applicable
terms and credits.

## What is libhybris?

The upstream libhybris project loads drivers compiled for Android from regular
Linux processes. Android drivers commonly link against the Bionic C library,
while the host process may use glibc, musl, or another native C library.
libhybris provides the compatibility layer needed to use those Android shared
objects outside a normal Android userspace.

This fork keeps that architectural goal but replaces selected Linux-specific
loader seams with Windows implementations. The Windows host owns PE modules;
the embedded loader owns Android ELF modules.

## Current status

The project currently contains a staged portability implementation:

- Windows host file I/O and positioned ELF reads
- ELF64/x86-64 header and program-header validation
- PT_LOAD reservation, commit, copying, BSS zero-fill, and page protection
- Q `ElfReader` integration for native Windows PT_LOAD loading
- Read-only ELF fragment loading
- Standalone x86-64 relocation primitives covering absolute, PC-relative, PLT,
  and core TLS relocation forms with overflow and bounds checking
- Windows FLS-backed PT_TLS backend with per-thread dynamic blocks and cleanup
- Typed SysV/Microsoft x64 ABI thunk helpers for supported signatures
- Windows `LoadTask`/filesystem search paths, including namespace paths,
  runpaths, and default paths
- Q TLS registration/unregistration hooks and typed constructor, destructor,
  and no-argument IFUNC lifecycle calls under `_WIN32`
- Linux regression coverage for selected Q linker units
- Reproducible x86-64 Q-linker/core build validation and portable TLS/
  relocation regression tests

The full Android dynamic-linker runtime is not complete. The full Q
translation-unit boundary still depends on POSIX/Bionic memory, allocator,
lock, and diagnostics headers. Relocations are not yet validated through a
complete Windows `soinfo::relocate` dependency graph, and arbitrary exported
Android calls still require a typed ABI signature.

JNI, Binder, graphics, media, Android properties, and other framework services
require external providers. This repository does not contain those providers
and does not claim generic support for libraries that require them.

## How to use the upstream project

On Linux, libhybris is normally paired with a stripped-down Android userspace
that provides the hardware adaptation services required by the target drivers.
Android is patched to remove processes and TLS behavior that conflict with the
host environment, and the resulting system is launched by the distribution's
init system or in a container.

Building against a particular Android version also requires matching Android
headers. Useful upstream and ecosystem references include:

- [libhybris](https://github.com/libhybris/libhybris)
- [Android Bionic](https://android.googlesource.com/platform/bionic/)
- [Android NDK](https://developer.android.com/ndk)
- [Mer hybris patches](https://github.com/mer-hybris/hybris-patches)
- [Halium hybris patches](https://github.com/halium/hybris-patches)
- [SailfishOS HADK](https://docs.sailfishos.org/Develop/HADK)
- [Halium](https://github.com/Halium)

The upstream project also documents header extraction and integrations for
graphics, audio, and Binder-backed services. Those integrations remain
external to this Windows portability fork.

## Source layout

```text
compat/        Android compatibility headers and adapters
hybris/        Loader, wrappers, and Q linker sources
utils/         Build and extraction utilities
*.c, *.cpp     Portability helpers and tests under hybris/common/q
```

## Reproducible build and test

The existing Linux-oriented build remains Autotools-based, while the
portability work has a dependency-light host regression suite. The checked-in
`.tool-versions` records the toolchain versions used for validation (the
Docker image is the canonical clean-room environment).

### Linux setup and checks

Install Docker, then build the project-local validation image. The image
installs all compiler, GoogleTest, Autotools, and fixture-generation
dependencies; after the image is built, test execution is offline:

```bash
docker build --tag libhybris-win:test .
docker run --rm libhybris-win:test
```

For a native Linux checkout, install GCC/G++, `libgtest-dev`, `pkg-config`,
Python 3, and the usual Autotools packages, then run:

```bash
make test
```

`make test` is the stable test entry point and runs `run-tests.sh`, which builds
and executes the Q linker unit tests. It also creates
`.build/minimal-x86_64.so`, a deterministic ELF64 ET_DYN fixture used for
format sanity validation. No Android rootfs is downloaded or checked in.
`make validate` is an alias suitable for CI. Remove generated output with
`make clean`.

To run the longer x86-64 core-loader build validation (it does not require an
Android rootfs):

```bash
./build-and-test-x86_64.sh
```

The current Linux GoogleTest baseline is 21 tests across five test binaries;
the runner also exercises the standalone relocation and TLS backends, for
seven test binaries in total.
The Windows validation path uses the native MSYS2 UCRT64 toolchain (`gcc`,
`g++`) and runs the resulting PE executables on Windows x64. Windows-specific
source seams are selected with `_WIN32` and do not import the Android NDK
sysroot wholesale.

To build the x86-64 Q linker and core library from the current checkout without
an external Android rootfs:

```bash
./build-and-test-x86_64.sh
```

To additionally run the Android `dlopen` smoke test, point the script at an
x86-64 Android rootfs. A different library can be selected with
`HYBRIS_SMOKE_LIBRARY`:

```bash
HYBRIS_ROOTFS=/path/to/android/system/lib64 ./build-and-test-x86_64.sh
```

On Windows with MSYS2/UCRT64, the native portability layer and ELF mapping
tests can be run with:

```bash
HYBRIS_ROOTFS=/c/path/to/android/rootfs ./build-and-test-windows.sh
```

This validates the Windows file reader, PT_LOAD reservation/commit/protection,
FLS-backed TLS backend, and x86-64 relocation primitives. The complete Q
linker still requires additional Windows replacements for the remaining
POSIX/Bionic synchronization and runtime seams.

### Windows MSYS2/UCRT64

Install the current MSYS2 distribution and use the **UCRT64** shell. Update
the package database and install the pinned toolchain class and test tools:

```bash
pacman -Syu
pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
  mingw-w64-ucrt-x86_64-gcc-libs make bash python
```

From the repository checkout in that shell, generate the portable fixture and
run the host unit suite with `make test`. To exercise the Windows ELF reader,
the native test currently needs an Android x86-64 rootfs:

```bash
export HYBRIS_ROOTFS=/c/path/to/android/rootfs
./build-and-test-windows.sh
```

The script expects `$HYBRIS_ROOTFS/system/lib64/libc.so` and runs the
relocation, TLS, and Windows ELF mapping tests. Use forward-slash MSYS paths;
the script handles MSYS2 argument conversion for the loader's embedded path
defaults. The generated minimal fixture is useful for parser-level checks but
is not a substitute for that rootfs smoke test.

### Autotools packaging/deployment validation

The full upstream install is optional for this portability suite. When Android
headers and their `pkg-config` metadata are available, validate the Autotools
distribution and install into a staging prefix (never `/usr` during checks):

```bash
cd hybris
autoreconf -fi
./configure --prefix="$PWD/../.build/stage" --enable-arch=x86-64 \
  --with-android-headers=/path/to/android-headers
make -j"$(nproc)"
make check
make DESTDIR="$PWD/../.build/package" install
```

The staged tree under `.build/package` is the deployment artifact for review
or packaging. It requires matching Android headers and providers; the
repository does not ship those dependencies.

## Scope and disclaimer

This is experimental research software, not a production-ready Android
runtime, compatibility guarantee, or replacement for the upstream project.
Android shared libraries may depend on Bionic, JNI, Binder, graphics, media,
device-specific services, or an exact Android userspace that is not supplied
here. Use it only with the relevant licenses and authorization for the Android
libraries and drivers being loaded.

Validation reports, generated fixtures, logs, and exploratory probes are kept
outside the tracked source tree and are intentionally not part of the source
commits.
