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
- Standalone x86-64 relocation primitives, including core TLS relocation forms
- Windows FLS-backed PT_TLS backend with per-thread dynamic blocks and cleanup
- Typed SysV/Microsoft x64 ABI thunk helpers for supported signatures
- Windows `LoadTask`/filesystem search paths, including namespace paths,
  runpaths, and default paths
- Q TLS registration/unregistration hooks and typed constructor, destructor,
  and no-argument IFUNC lifecycle calls under `_WIN32`
- Linux regression coverage for selected Q linker units

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

## Build and test

The existing Linux-oriented build remains Autotools-based. A local Q unit-test
runner is available:

```bash
./run-tests.sh
```

The current Linux unit-test baseline is 19 tests across four test binaries.
The Windows validation path uses the native MSYS2 UCRT64 toolchain (`gcc`,
`g++`) and runs the resulting PE executables on Windows x64. Windows-specific
source seams are selected with `_WIN32` and do not import the Android NDK
sysroot wholesale.

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
