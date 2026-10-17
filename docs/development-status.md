# Development status

## VERIFIED

- Reproducible Linux host test entry point (`make test`), with 9 test binaries
  passing.
- Windows x64 Q-linker fixture flow: dependencies, relocations, constructors,
  IFUNC, dynamic TLS, symbol lookup, and close.
- Windows ELF64/x86-64 reader and PT_LOAD mapping against emulator `libc.so`.
- Linux real-rootfs smoke loading emulator `libm.so` and resolving `cos`.
- GOTPCREL-family relocation coverage and Windows ELF version-field layout.
- NDK-generated x86-64 TLSGD/TLSLD fixtures, including two-thread isolation and
  initialization through the native Windows FLS backend.
- NDK-generated x86-64 initial-exec fixture execution through the synthetic
  guest static-TLS block, including two-thread isolation.
- Native Windows Q smoke coverage for `dladdr`, `dlvsym` failure behavior, and
  `dl_iterate_phdr`.
- Native Windows repeated eight-cycle fixture load/unload stress coverage.
- ABI thunk regression coverage for mixed scalar arguments, pair returns,
  callbacks, and repeated stack-preservation checks.

## TESTED / PARTIAL

- Windows FLS-backed guest TLS.
- Synthetic static/initial-exec TLS and canonical NDK `%fs` access rewriting;
  broader prebuilt-library instruction coverage remains incomplete.
- Typed SysV/Microsoft x64 ABI thunk surface; direct stack-passed arguments and
  asynchronous callbacks remain outside the current public API.
- Symbol versioning and namespace/search-path implementation.
- `dladdr`, `dlvsym`, and `dl_iterate_phdr` internal paths; public Windows
  end-to-end coverage is incomplete.

## IMPLEMENTED / TESTED

- Hardened APS2/SLEB128 decoding against truncation, invalid flags, zero-sized
  groups, oversized groups, and decoder-width overflow; `make test` passes.
- Added a machine-readable compatibility matrix and durable engineering ledger.
- Expand real Android library execution coverage.

## IN_PROGRESS

- Design guest static/initial-exec TLS access for prebuilt Android libraries.

## BLOCKED OR UNSUPPORTED

- Full prebuilt Android initial-image static/IE TLS execution on native Windows.
- Complete TLSGD, TLSLD, and TLSDESC execution.
- Generic variadic ABI forwarding.
- JNI/ART, Binder, graphics, media, and HAL service integrations.

## Next verified work

1. Extend the verified guest static/initial-exec transformation with a complete
   x86-64 instruction decoder and safe patch-window handling for prebuilt
   Android `libc.so`; preserve the explicit failure boundary for unsupported
   forms.
2. Add namespace/search-path and partial-load cleanup cases where the existing
   Q API can exercise them without redesign.
