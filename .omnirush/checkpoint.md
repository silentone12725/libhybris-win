# Engineering checkpoint

- Current commit: `07c422b test: expand ABI thunk regression coverage`
- Branch: `master`
- Remote: `origin/master` at `efab890`; local branch is ahead by 11 commits.
- Working tree at checkpoint creation: clean after ABI regression coverage.
- Active task: continue final cross-platform verification, ABI boundary review,
  and the guest static/initial-exec TLS design needed for real Android libraries.
- Linux baseline and post-change tests: local and Docker `make test` both pass,
  9 test binaries; `build-and-test-x86_64.sh` builds successfully without a
  rootfs; prior real-rootfs `libm.so` and `libz.so` operation smokes passed.
- Windows prerequisites: native MSYS2/UCRT64 host available through SSH port
  2222; Android NDK r26d exists; emulator `emulator-5554` reports x86-64.
- Emulator artifacts: the local `/tmp/android-x86_64-rootfs` is currently
  unavailable and must be repulled; the Windows copy was previously placed
  under `C:\Users\Podman\android-x86_64-rootfs`.
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
  execution remains blocked by libc initial-image TLS.
- Next action: restore the emulator rootfs, capture complete current Windows
  output, and then implement or conclusively scope the guest static/initial-exec
  TLS path; the legacy `mm`/`n`/`o` APS2 copies were audited and are outside the
  active Q Windows build.
