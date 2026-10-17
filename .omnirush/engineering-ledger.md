# Engineering ledger

Statuses: `NOT_STARTED`, `IN_PROGRESS`, `BLOCKED`, `IMPLEMENTED`, `TESTED`,
`VERIFIED`.

| ID | Task | Dependencies | Evidence | Status |
| --- | --- | --- | --- | --- |
| ENG-001 | Establish baseline and prerequisites | None | Clean `a38c23e`; emulator `emulator-5554`; MSYS2/NDK host; baseline logs in `/tmp` | VERIFIED |
| ENG-002 | Document architecture, matrix, build, research, limitations, status | ENG-001 | `docs/*.md` | VERIFIED |
| ENG-003 | Harden APS2/SLEB128 malformed-input handling | Q iterator callers | `make test`; malformed SLEB/APS2 tests; native Linux and Windows Q builds | TESTED |
| ENG-004 | Implement remaining TLS relocation models | NDK fixture generation; guest TLS design | Native Windows TLSGD/TLSLD fixture smoke passes; TLSDESC remains | TESTED |
| ENG-005 | Decide and implement safe prebuilt IE/LE TLS execution | Windows TLS design | Synthetic guest TLS and canonical NDK IE fixture pass; native Windows real `libc.so` still fails closed on an unrewritable sequence | BLOCKED |
| ENG-006 | Complete priority dynamic-loader API tests | Q API internals | Native Windows fixture covers `dladdr`, `dlvsym` missing-symbol path, and `dl_iterate_phdr` | TESTED |
| ENG-007 | Expand ABI bridge coverage | Signature definition | Typed thunk tests cover mixed scalar arguments, pair returns, callbacks, and repeated stack-preservation checks; public API has no >4-argument signature | TESTED |
| ENG-008 | Exercise additional real Android libraries | Dependency-compatible artifacts | Linux emulator smoke executes `libm.so:cos` and `libz.so:crc32` | TESTED |
| ENG-009 | Windows stress/error audit | Core APIs and fixtures | Native Windows 8-cycle Q fixture load/unload smoke; missing-library failure path checked | TESTED |
| ENG-010 | Final cross-platform verification and documentation reconciliation | ENG-003..ENG-009 | Local `make test`; emulator-rootfs Linux `libm.so`/`libz.so` operation smokes; native Windows relocation/ELF-reader and Q/core fixture smokes; expected real-`libc.so` IE TLS rejection | TESTED |

## Evidence rule

Compilation alone is not completion. A task becomes `VERIFIED` only after its
behavior is exercised on the relevant platform, negative paths are checked,
and the compatibility matrix and checkpoint agree with the result.
