# Engineering ledger

Statuses: `NOT_STARTED`, `IN_PROGRESS`, `BLOCKED`, `IMPLEMENTED`, `TESTED`,
`VERIFIED`.

| ID | Task | Dependencies | Evidence | Status |
| --- | --- | --- | --- | --- |
| ENG-001 | Establish baseline and prerequisites | None | Clean `a38c23e`; emulator `emulator-5554`; MSYS2/NDK host; baseline logs in `/tmp` | VERIFIED |
| ENG-002 | Document architecture, matrix, build, research, limitations, status | ENG-001 | `docs/*.md` | VERIFIED |
| ENG-003 | Harden APS2/SLEB128 malformed-input handling | Q iterator callers | `make test`; malformed SLEB/APS2 tests; native Linux and Windows Q builds | TESTED |
| ENG-004 | Implement remaining TLS relocation models | NDK fixture generation; guest TLS design | Current dynamic FLS fixture only | NOT_STARTED |
| ENG-005 | Decide and implement safe prebuilt IE/LE TLS execution | Windows TLS design | Native Windows real `libc.so` failure is reproduced | BLOCKED |
| ENG-006 | Complete priority dynamic-loader API tests | Q API internals | Existing internal `dladdr`/`dl_iterate_phdr` paths | NOT_STARTED |
| ENG-007 | Expand ABI bridge coverage | Signature definition | Current typed thunk tests | NOT_STARTED |
| ENG-008 | Exercise additional real Android libraries | Dependency-compatible artifacts | Emulator API 35 x86-64 rootfs | NOT_STARTED |
| ENG-009 | Windows stress/error audit | Core APIs and fixtures | Native Windows host available over SSH | NOT_STARTED |
| ENG-010 | Final cross-platform verification and documentation reconciliation | ENG-003..ENG-009 | Commands in `docs/build-and-test.md` | NOT_STARTED |

## Evidence rule

Compilation alone is not completion. A task becomes `VERIFIED` only after its
behavior is exercised on the relevant platform, negative paths are checked,
and the compatibility matrix and checkpoint agree with the result.
