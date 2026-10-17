# Development status

## VERIFIED

- Reproducible Linux host test entry point (`make test`), with 9 test binaries
  passing at baseline commit `a38c23e`.
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

## TESTED / PARTIAL

- Windows FLS-backed guest TLS.
- Typed SysV/Microsoft x64 ABI thunk surface.
- Symbol versioning and namespace/search-path implementation.
- `dladdr`, `dlvsym`, and `dl_iterate_phdr` internal paths; public Windows
  end-to-end coverage is incomplete.

## IMPLEMENTED / TESTED

- Hardened APS2/SLEB128 decoding against truncation, invalid flags, zero-sized
  groups, oversized groups, and decoder-width overflow; `make test` passes.
- Added a machine-readable compatibility matrix and durable engineering ledger.
- Expand real Android library execution coverage.

## IN_PROGRESS

- Compile and inspect NDK-generated TLSDESC fixtures.
- Add priority dynamic-loader stress and namespace coverage.

## BLOCKED OR UNSUPPORTED

- Prebuilt Android initial-image static/IE TLS execution on native Windows.
- Complete TLSGD, TLSLD, and TLSDESC execution.
- Generic variadic ABI forwarding.
- JNI/ART, Binder, graphics, media, and HAL service integrations.

## Next verified work

1. Convert SLEB128 and APS2 decoding to checked, non-fatal error propagation.
2. Add compiled TLSGD/TLSLD/TLSDESC fixtures and determine the safe Windows
   execution transformation.
3. Add API and stress coverage for the priority dynamic-loader surface.
4. Exercise additional real emulator libraries through native Windows where
   their dependency and TLS requirements fit the declared boundary.
