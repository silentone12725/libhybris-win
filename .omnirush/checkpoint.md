# Engineering checkpoint

- Checkpoint baseline commit: `58a072c docs: update engineering checkpoint`
- Branch: `master`
- Remote: `origin/master` at `efab890`; local branch is ahead by 11 commits.
- Working tree at checkpoint creation: clean after ABI regression coverage.
- Follow-up commits: `f949982` reconciled verification docs; `7d464e8` made the
  temporary test-binary directory deterministic and stale-binary safe; `58a072c`
  recorded that follow-up state.
- Active task: continue final cross-platform verification, ABI boundary review,
  and the guest static/initial-exec TLS design needed for real Android libraries.
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
  execution was rechecked and remains blocked by libc initial-image TLS; the
  diagnostic reports the IE access model explicitly.
- Next action: implement or conclusively scope the guest static/initial-exec TLS
  path; the legacy `mm`/`n`/`o` APS2 copies were audited and are outside the
  active Q Windows build.
