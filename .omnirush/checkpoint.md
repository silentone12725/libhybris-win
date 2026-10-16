# Engineering checkpoint

- Current commit: `01b29d9 fix: reject malformed packed relocations`
- Branch: `master`
- Remote: `origin/master` at `efab890`; local branch is ahead by 8 commits.
- Working tree at checkpoint creation: clean after the APS2 hardening commit.
- Active task: continue from APS2 hardening into TLS relocation models and
  priority dynamic-loader API coverage.
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
  Q fixture runtime passed, and core fixture smoke passed using dynamic TLS.
- Next action: compile and inspect NDK-generated TLSGD/TLSLD/TLSDESC fixtures,
  then implement the first supported dynamic model with end-to-end tests.
