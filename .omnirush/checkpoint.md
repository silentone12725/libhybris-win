# Engineering checkpoint

- Checkpoint baseline commit: `512fb8b fix: preserve guest TLS rewrite state`
- Branch: `master`
- Remote: `origin/master` at `efab890`; local branch is ahead by 23 commits.
- Working tree at checkpoint creation: clean after guest-TLS state preservation
  and documentation reconciliation.
- Follow-up commits: `f949982` reconciled verification docs; `7d464e8` made the
  temporary test-binary directory deterministic and stale-binary safe; `58a072c`
  recorded that follow-up state.
- Active task: continue final cross-platform verification and extend the partial
  guest static/initial-exec TLS rewrite needed for real Android libraries.
- Linux baseline and post-change tests: local and Docker `make test` both pass,
  9 test binaries; emulator-rootfs `build-and-test-x86_64.sh` runs passed for
  `libm.so:cos(0)` and `libz.so:crc32("hello")`.
- Windows prerequisites: native MSYS2/UCRT64 host available through SSH port
  2222; Android NDK r26d exists; emulator `emulator-5554` reports x86-64.
- Emulator artifacts: `/tmp/android-x86_64-rootfs` was repulled from
  `emulator-5554`; the Windows copy is under
  `C:\Users\Podman\android-x86_64-rootfs`.
- Known critical failure: native Windows execution of real Android `libc.so`
  reaches the unsupported initial-exec/static TLS path.
- Native Windows post-change evidence: relocation/ELF-reader tests passed,
  Q fixture runtime passed, core fixture smoke passed using dynamic TLS, and
  NDK-generated TLSGD/TLSLD fixtures passed with two-thread isolation; the Q
  fixture also passed `dladdr`, `dlvsym` missing-symbol,
  `dl_iterate_phdr`, missing-library cleanup, and eight repeated load/unload
  cycles.
- Linux emulator evidence includes representative `libm.so:cos(0)` and
  `libz.so:crc32("hello")` operations. Native Windows real Android library
  execution was rechecked and remains blocked by an unrewritable libc
  initial-image TLS sequence; the loader fails closed. The NDK global-dynamic,
  local-dynamic, and initial-exec fixture smoke passes with two-thread
  isolation.
- The latest native rerun could not be repeated because the Windows MSYS2 SSH
  endpoint on `127.0.0.1:2222` refused the connection. The speculative
  Windows-only `libc.so` constructor bypass and arithmetic `%fs` rewrite were
  removed; arithmetic forms remain explicitly unsupported until they have
  focused ABI and flags tests.
- Next action: restore the Windows test host, rerun the native fixture and real
  `libc.so` smoke against commit `512fb8b`, then either add evidence for another
  narrowly supported access form or preserve the explicit fail-closed boundary.
