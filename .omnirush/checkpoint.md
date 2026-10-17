# Engineering checkpoint

- Checkpoint baseline commit: `a1b0b40 feat: add synthetic Windows static TLS support`
- Branch: `master`
- Remote: `origin/master` at `efab890`; local branch is ahead by 23 commits.
- Working tree at checkpoint creation: clean after synthetic static-TLS fixture
  coverage and documentation reconciliation.
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
- Next action: complete x86-64 instruction decoding and safe patch-window
  handling for the remaining real-libc access forms; the legacy `mm`/`n`/`o`
  APS2 copies were audited and are outside the active Q Windows build.
