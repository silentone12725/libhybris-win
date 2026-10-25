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

## Rebuild on the fresh VM (2026-10-25) — done, with new fixes

Rebuilt the whole in-process path from the recovered sources and got much further
than the pre-wipe frontier. Harness + build scripts are now preserved here
(`smoke2.c`, `build_drm.sh` = libdrm_client.dll + smoke2, `build_qso.sh` = q.so only)
so they are never VM-only again. VM layout: sources `C:\adam-src\native` + `C:\adam-src\smoke2.c`;
rootfs `C:\rootfs\system\lib64`; q.so `C:\storage\hybris-linker\q.so`; build out `C:\adam-build`.

Four root causes fixed this session (all committed to master):
1. **Hook-table cast** — `_bionic_pthread_once` sysv_abi function-pointer cast syntax.
2. **Missing `libdl.so`** — the re-fetched rootfs lacked it. libstoreservicescore.so
   (and others) DT_NEEDED `libdl.so`; the Q linker adds every DT_NEEDED as a load task
   with no skip, so the file must exist. It is a *version-definition stub* (exports no
   functions, just defines version `LIBC` and satisfies the soname); the real
   dlopen/dlsym/dlclose come from hybris hooks, dl_iterate_phdr from libc. The original
   is preserved in `apple-music-linux-hybris/drm/rootfs/system/lib64/libdl.so`
   (sha1 0debd063…, 13864 bytes) — copy it into any fresh rootfs.
3. **TLS rewriter scanned data-only libs** — libicudata parks a ~10 MB data blob in an
   R+E PT_LOAD with a zero-length `.text`. `find_exec_ranges` conflated "no exec
   sections" with "couldn't read headers" and fell back to scanning the whole segment,
   decoding locale data as x86 and aborting on a 3-byte fs: false positive. Fixed to
   treat a readable section table as authoritative (empty exec set ⇒ scan nothing).
4. **`__errno` not hooked** — the hook table only had the glibc name `__errno_location`;
   bionic uses `__errno`. `__system_properties_init` fell through to bionic's own
   `__errno`, read an uninitialised thread pointer, and returned a bogus errno pointer.
   Hooked both names to `_win32_errno_location`.

## New frontier (2026-10-25)
Init now loads all 98 libraries and runs deep into `drm_init_internal`. It crashes in
**`hybris_abi_call_sysv_ctor`** (q.so, the Windows→SysV constructor trampoline) calling a
**DT_INIT_ARRAY / constructor function pointer for `libc++_shared.so`** that is garbage:
target `~0x…1A12BE0` lands in a non-ELF region on a padding `0x00` byte just before a real
function epilogue (`49 89 c3 49 8b 03 41 5f…`), faulting as `add [rcx-0x77],cl` with rcx=0
(write to 0xFFFFFFFFFFFFFF89). r8 points into libc++_shared.so (+0x4e430); the return
address on the stack is `hybris_abi_call_sysv_ctor` (q.so RVA 0x2b2eb).

The faulting region has no ELF header at its VirtualQuery AllocationBase, and the RIP
bytes look like a trampoline/function epilogue (`mov rax,[r11]; pop r15…r10`). r8 points
into libc++_shared.so; the stack return addresses are in q.so around
`hybris_abi_call_sysv_ctor` (RVA ~0x2b2eb/0x2b3fb) and nearby linker frames.

### Ruled out this session
- **Non-contiguous segment mapping.** `ElfReader::ReserveAddressSpace`
  (`linker_phdr.cpp`) reserves one contiguous block of `phdr_table_get_load_size`
  (max_vaddr−min_vaddr) via `win_elf_image_reserve_aligned`, then `LoadSegments` maps
  each PT_LOAD into it at a single `load_bias`. Segments are contiguous, so a simple
  per-segment bias mismatch is not the cause.
- **ABI trampoline.** `hybris_abi_call_sysv_ctor` (`common/abi_thunks.c`) is correct: it
  rejects only 0/UINTPTR_MAX then calls with the `HYBRIS_ABI_SYSV` convention. It is not
  corrupting registers; the pointer it is handed is simply bad.
- **ctor_whitelist (tried and reverted).** Re-added a run-if-listed whitelist seeded with
  `libstoreservicescore.so`: it removed the libc++_shared crash but moved it to a
  null-deref (`READ [0x28]`) inside libstoreservicescore's own constructor, because its
  dependencies' constructors were then skipped. libstoreservicescore needs libc++_shared's
  globals, but libc++_shared's constructor is the one crashing — a circular dependency
  that proves the whitelist cannot fix this. Reverted to the clean baseline.

### Refined frontier / next step
With all constructors running (clean baseline), a constructor invoked via
`hybris_abi_call_sysv_ctor` jumps to / executes a **bad pointer in a non-ELF region**
(offset 0x2be0, i.e. larger than a single 0x1000 TLS stub page, so not obviously a stub
either). Open hypotheses to disambiguate with runtime data:
1. a mis-relocated `DT_INIT_ARRAY` entry (dump libc++_shared's init_array vs where its
   code actually maps);
2. a TLS-rewriter stub control-flow error reached from a constructor's rewritten fs:
   access (log `g_stub_pages` ranges and check whether the faulting region is one);
3. a constructor executing correctly but dereferencing a null global.
Use cdb (`recovery/`-style) but note first-chance RELRO faults are handled by smoke2's VEH
(use `sxd av` and make the VEH's diagnostic reads fault-proof — already done via `safe_rd`
so the handler no longer self-crashes while dumping). smoke2's VEH now prints registers,
RIP bytes, ELF SONAME of the faulting region, and a fault-proof stack-word→module dump.
