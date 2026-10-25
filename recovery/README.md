# Windows DRM port — recovery notes

The build VM was re-imaged. The VM's ~900-line `hybris/common/windows_hook_table.c`
and 7 unpushed session commits were lost (never committed/pushed; only a ~220-line
early hook table survived in this repo). These files preserve the fixes so they can
be re-applied once the hook table is rebuilt.

## Root cause common to all fixes
Apple's Android `.so` libraries use the **System V AMD64 ABI**; the Windows host
functions and our hook implementations are **Windows x64 ABI**. Crossing that
boundary unbridged (a) reads args from the wrong registers and (b) spills
nonvolatile registers into the caller's 32-byte shadow space, which System V code
never allocates — corrupting the guest's stack frame. Fixes = `sysv_abi` wrappers
(so the compiler bridges the ABI and keeps spills in the callee frame) plus, where
struct layouts differ (bionic cond/rwlock), small reimplementations.

## Status
| Fix | What | State |
|-----|------|-------|
| #2 | `instruction_length` opcode coverage (0xc6/0x80/0xf6…) in the TLS rewriter | **already present** in this repo's `x86_64_guest_tls_rewriter.cpp` |
| #4 | TLS rewriter: skip 0x00/0xcc padding after `jmp`/`ret` so `fs:` sweeps re-sync | **applied + pushed** (commit on master) |
| #5 | Populate guest bionic `TP[1]` (`TLS_SLOT_THREAD_ID`) in the static TCB | **applied + pushed** (commit on master) |
| #1 | pthread ABI: `sysv_abi` on `_hybris_win32_*`/`_bionic_mutex_*`; bionic `_bionic_cond_*`/`_rwlock_*`/`_attr_*`; `_bionic_pthread_create` trampoline; kill/sigmask stubs | **pending** — `recovery/fix1_pthread_abi.pl` (needs rebuilt hook table) |
| #3 | host libc ABI: `sysv_abi` malloc/mem/dl bridges; `sysv_abi` on `_safe_*`/`_stub_*` | **pending** — `recovery/fix3_host_libc_abi.pl` |
| #6 | hook guest `mmap`/`munmap`/`mprotect` → VirtualAlloc (bionic's are raw syscalls) | **pending** — `recovery/fix6_mmap.pl` |
| #7 | `sysv_abi` on variadic `_win32_*` log hooks | **pending** — `recovery/fix7_win32_variadic_abi.pl` |

Fixes #1/#3/#6/#7 extend the lost full hook table, so apply them **after** the hook
table is rebuilt. Run each with `HYBRIS_COMMON=/path/to/hybris/common perl recovery/fixN_*.pl`.

## Two manual pieces (not in the .pl files)
1. **ctor whitelist** (`hybris/common/q/linker_soinfo.cpp`): add `"libstoreservicescore.so"`
   to `ctor_whitelist[]` so its `DT_INIT_ARRAY` constructors run (FootHillConfig needs
   the globals they create). The VM also needed the stack fix below for those ctors.
2. **Committed stack for the test/host process**: Linux large-frame code skips Windows'
   guard page (no `__chkstk`), so give the process a fully-committed stack. For smoke2:
   link with `-Xlinker --stack -Xlinker 0x4000000,0x4000000` (64 MB reserve == commit).
   The shipping engine process needs the same.

## Rebuild procedure (fresh VM)
1. Clone this repo (it now has #2/#4/#5 and the `recovery/` patches).
2. Re-fetch Apple libs into `C:\rootfs\system\lib64` via `apple-music-linux`'s
   `scripts/fetch-fairplay-libs.sh` (pinned + SHA-256 in `drm/fairplay-libs.lock`).
3. Bring back the native wrapper sources (from `Git Projects/wrapper`: `drm_lib.c`,
   `main.c`, `main.cpp`, `cmdline.c`, `cJSON.c`, `guard.cpp`, `hybris_stubs.c`).
4. Rebuild the hook table (`windows_hook_table.c`) — the lost VM version had, beyond
   the surviving 220-line base: `_bionic_mutex_*` (int32 spinlock), `_safe_*` string
   wrappers, `_stub_*` helpers, and a large `win32_hooks[]` covering dlopen/pthread/
   malloc/mem/stdio/math and `HA(syscall, _stub_syscall)`. Then apply fixes #1/#3/#6/#7.
5. Build q.so (UCRT64 g++ `-std=c++17`), libdrm_client.dll, smoke2 (with the stack flag).

## Frontier when the VM died
`drm_lib_init` → `drm_init_internal` → `FootHillConfig::config` **completed**; init
reached `DeviceGUID::instance` (which returned `GUID.obj = NULL`) and crashed in
`DeviceGUID::configure`. **Next step:** find why `DeviceGUID::instance` returns NULL
(likely another stubbed/ABI'd dependency inside it) rather than chasing the
`configure` null-deref. Beyond that: lease manager, recovery thread, then the
network/FairPlay provisioning that `drm_lib_get_account` → `ACCOUNT_OK` requires.
