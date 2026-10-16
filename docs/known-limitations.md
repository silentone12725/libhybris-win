# Known limitations

## Critical compatibility limitations

### Prebuilt initial-exec/static TLS on Windows

The current Windows guest TLS backend allocates module blocks through FLS and
serves dynamic `__tls_get_addr` requests. It does not provide a guest thread
pointer for direct x86-64 `%fs` accesses. Android's initial-image `libc.so`
contains such accesses and therefore cannot currently be executed through the
Windows core wrapper.

The loader rejects this case instead of writing an invalid Linux TPOFF value.
The native Windows core smoke uses a dynamic-TLS fixture by default; setting
`HYBRIS_WINDOWS_CORE_SMOKE_REAL_ANDROID=1` exposes the unsupported path.

### Missing TLS relocation models

TLSGD, TLSLD, and TLSDESC are not complete end-to-end models. Arithmetic tests
for selected TLS forms do not imply that generated Android instruction
sequences execute correctly on Windows.

### Typed ABI boundary

The ABI bridge supports documented typed signatures only. Generic variadic
forwarding and arbitrary C++ ABI interoperability are not supported.

## Explicitly unsupported host facilities

Several compatibility hooks return `ENOSYS` where there is no safe Windows
semantic adapter yet, including shared-memory and selected filesystem,
scheduling, timer, allocation, and locale facilities. They must not be changed
to fabricated success values.

## External integrations

JNI/ART, Binder, graphics, media, and device-specific HAL providers require
external Android services, matching libraries, and target-specific host
adapters. They are not included in the core loader completion target.

## Validation limitations

- The Linux reference path has real emulator `libm.so` load and `cos` execution
  coverage.
- The Windows path has real emulator `libc.so` ELF-reader coverage and complete
  Q fixture execution coverage, but not real `libc.so` execution.
- Broader real-library coverage must include representative operations rather
  than only loading or symbol lookup.
