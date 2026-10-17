# Known limitations

## Critical compatibility limitations

### Prebuilt initial-exec/static TLS on Windows

The Windows guest TLS backend allocates module blocks through FLS and also
maintains a synthetic guest static-TLS block. The Q x86-64 loader can rewrite
the canonical NDK initial-exec sequences used by the checked-in TLS fixture,
including short `%fs:[register+disp]` forms, without changing host FS/GS.
Android's initial-image `libc.so` contains additional short and complex access
sequences that are not yet transformed safely and therefore cannot currently be
executed through the Windows core wrapper.

The loader rejects unrewritable cases instead of writing an invalid Linux TPOFF
value. The native Windows TLS smoke now covers global-dynamic, local-dynamic,
and initial-exec fixtures; setting `HYBRIS_WINDOWS_CORE_SMOKE_REAL_ANDROID=1`
still exposes the unsupported real-library path.

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
