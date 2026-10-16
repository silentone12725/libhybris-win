# Engineering checkpoint

- Current commit: `01b29d9 fix: reject malformed packed relocations`
- Branch: `master`
- Remote: `origin/master` at `efab890`; local branch is ahead by 8 commits.
- Working tree at checkpoint creation: clean after the APS2 hardening commit.
- Active task: continue from TLSGD/TLSLD and priority loader APIs into
  namespace/lifetime stress and real-library expansion.
- Linux baseline and post-change tests: `make test` passed, 9 test binaries;
  `build-and-test-x86_64.sh` built successfully; real-rootfs `libm.so` smoke
  loaded and resolved `cos`.
- Windows prerequisites: native MSYS2/UCRT64 host available through SSH port
  2222; Android NDK r26d exists; emulator `emulator-5554` reports x86-64.
- Emulator artifacts: `/tmp/android-x86_64-rootfs` contains pulled system and
  runtime files; Windows copy is under `C:\Users\Podman\android-x86_64-rootfs`.
- Known critical failure: native Windows execution of real Android `libc.so`
  reaches the unsupported initial-exec/static TLS path.
- Native Windows post-change evidence: relocation/ELF-reader tests passed,
  Q fixture runtime passed, core fixture smoke passed using dynamic TLS, and
  NDK-generated TLSGD/TLSLD fixtures passed with two-thread isolation; the Q
  fixture also passed `dladdr`, `dlvsym` missing-symbol, and `dl_iterate_phdr`.
- Next action: inspect namespace/lifetime behavior under repeated load/unload,
  then expand real Android library execution coverage.
