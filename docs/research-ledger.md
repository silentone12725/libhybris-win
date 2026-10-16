# Research ledger

This ledger records decisions that affect the compatibility boundary. It
contains source pointers and conclusions, not private credentials or machine
secrets.

| ID | Question | Sources consulted | Decision |
| --- | --- | --- | --- |
| R-001 | How should Android x86-64 TLS be represented on Windows? | x86-64 psABI; Drepper TLS ABI paper; Microsoft FLS/TEB documentation; `linker_tls.cpp`; `windows_tls_backend.*` | Keep host FS/GS and TEB untouched. Use FLS-backed guest dynamic TLS. Do not claim prebuilt IE/LE execution until a guest access transformation or isolated architecture is proven. |
| R-002 | Why does emulator `libc.so` fail in native Windows core smoke? | `linker.cpp` TLS relocation path; emulator ELF; Windows TLS backend | `libc.so` is an initial image with direct initial-exec TLS. The current FLS-only backend cannot satisfy its `%fs` accesses. The smoke test uses a dynamic-TLS fixture by default and reports the limitation explicitly. |
| R-003 | What relocation coverage is required first? | x86-64 ELF psABI; Android Bionic linker relocation code; NDK-generated fixtures | Implement and test common absolute, PC-relative, PLT, GOTPCREL, packed, and initial-exec arithmetic before adding less common TLS models. |
| R-004 | How should malformed APS2 data fail? | Android packed relocation field ordering; local `soinfo::relocate()` boolean contract | Replace aborting SLEB128 reads with checked reads, propagate iterator invalidity through `soinfo::relocate()`, and reject group/count arithmetic errors without process termination. |
| R-005 | What is the supported product boundary? | Upstream libhybris architecture; available emulator and NDK artifacts | Target a dependable Windows x64 ELF runtime for a documented subset of Android x86-64 libraries. JNI, ART, Binder, graphics, media, and HAL providers remain separate integrations requiring external dependencies. |
| R-006 | What counts as real-library evidence? | Test directive; emulator inventory; current smoke harness | A library must be loaded and a representative operation executed. Parsing or resolving one symbol is recorded separately and is not library-wide support. |

## Open research

- Determine whether a safe Windows-only instruction transformation can support
  canonical Android IE/LE TLS sequences without changing host segment bases.
- Inspect NDK compiler output for TLSGD, TLSLD, and TLSDESC on x86-64 Android.
- Compare Bionic `dladdr`, `dlvsym`, and `dl_iterate_phdr` contracts against the
  current Q implementation and Windows wrapper hooks.
