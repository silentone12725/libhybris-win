# Architecture

## Scope

`libhybris-win` embeds the Android Q ELF linker in a native Windows x64
process. The Windows PE loader owns the host process and the embedded Q linker
maps, relocates, resolves, and executes Android x86-64 ELF shared objects.

This is a native library runtime, not an Android framework or APK runtime. JNI,
ART, Binder, graphics, media, HAL services, and device providers are separate
integration targets and are not implied by successful ELF loading.

## Layers

1. **Windows host seams**
   - `windows_elf_host.*` reserves, commits, copies, protects, and releases
     ELF mappings using Windows virtual memory APIs.
   - `windows_elf_reader.*` validates ELF64/x86-64 files and reads headers and
     program headers with positioned I/O.
   - `windows_tls_backend.*` provides per-thread/per-fiber guest TLS blocks
     through FLS without changing the Windows TEB or host segment registers.

2. **Q linker**
   - Maps PT_LOAD and PT_TLS segments.
   - Resolves `DT_NEEDED`, symbol versions, constructors, destructors, IFUNCs,
     namespaces, and relocation tables.
   - Uses the Android/Bionic linker interfaces retained under
     `hybris/common/q`.
   - Exposes the priority loader APIs (`dladdr`, `dlvsym`, and
     `dl_iterate_phdr`) through the Windows core forwarding layer.

3. **Bionic compatibility seams**
   - Redirects selected Bionic runtime operations to the host implementation.
   - Uses the Windows hook table and environment-backed properties where the
     Android process environment is unavailable.
   - Explicitly returns unsupported errors for facilities outside the target.

4. **ABI bridge**
   - `abi_thunks.*` handles the documented typed SysV/Microsoft x64 boundary.
   - Calls across the boundary require a known signature. Arbitrary variadic
     or general C++ ABI forwarding is not promised.

## TLS model

The Windows implementation supports guest dynamic TLS through the FLS backend
and the SysV-ABI `__tls_get_addr` path. The Q linker maps that guest symbol to
its host-safe `__hybris_tls_get_addr` implementation when resolving Android
GD/LD modules. NDK-generated global-dynamic and local-dynamic fixtures are
executed on two Windows threads in the native smoke suite. It deliberately does
not change the Windows thread pointer or FS/GS bases.

Android x86-64 `libc.so` is an initial image and contains direct initial-exec
TLS relocations. A normally loaded Windows module cannot safely consume those
relocations from the current FLS-only backend. The native Windows core smoke
therefore uses the Android NDK dynamic-TLS fixture, while the real rootfs
`libc.so` is validated by the Windows ELF reader and real Android libraries are
loaded by the Linux reference path.

Supporting unmodified prebuilt IE/LE code requires a guest TLS access design,
such as a verified instruction transformation or a separate execution process;
assigning Linux TPOFF values to the Windows process is not correct.

## Error boundaries

Malformed ELF and relocation data must fail through the linker's boolean/error
path. Unsupported host services remain explicit failures rather than fabricated
success. The compatibility matrix records whether a behavior is implemented,
partially implemented, unsupported, or externally blocked.
