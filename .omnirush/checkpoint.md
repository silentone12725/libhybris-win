# Engineering checkpoint

- Current commit: `a38c23e fix: scope Windows core smoke to supported TLS`
- Branch: `master`
- Remote: `origin/master` at `efab890`; local branch is ahead by 8 commits.
- Working tree at checkpoint creation: clean before documentation changes.
- Active task: establish durable engineering baseline and documentation.
- Linux baseline: `make test` passed, 9 test binaries; `build-and-test-x86_64.sh`
  built successfully and skipped rootfs smoke when no rootfs was supplied.
- Windows prerequisites: native MSYS2/UCRT64 host available through SSH port
  2222; Android NDK r26d exists; emulator `emulator-5554` reports x86-64.
- Emulator artifacts: `/tmp/android-x86_64-rootfs` contains pulled system and
  runtime files; Windows copy is under `C:\Users\Podman\android-x86_64-rootfs`.
- Known critical failure: native Windows execution of real Android `libc.so`
  reaches the unsupported initial-exec/static TLS path.
- Next action: commit the durable docs, then harden checked SLEB128/APS2
  decoding and run Linux plus native Windows regression tests.
