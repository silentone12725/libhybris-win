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
- Native Windows Q smoke coverage for `dladdr`, `dlvsym` failure behavior, and
  `dl_iterate_phdr`.
- Native Windows repeated eight-cycle fixture load/unload stress coverage.
- ABI thunk regression coverage for mixed scalar arguments, pair returns,
  callbacks, and repeated stack-preservation checks.

## TESTED / PARTIAL

- Windows FLS-backed guest TLS.
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

- Prebuilt Android initial-image static/IE TLS execution on native Windows.
- Complete TLSGD, TLSLD, and TLSDESC execution.
- Generic variadic ABI forwarding.
- JNI/ART, Binder, graphics, media, and HAL service integrations.

## Next verified work

1. Determine whether a safe guest static/initial-exec TLS transformation can
   support prebuilt Android `libc.so`; otherwise preserve the explicit block.
2. Add namespace/search-path and partial-load cleanup cases where the existing
   Q API can exercise them without redesign.
