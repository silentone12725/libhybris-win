# Compatibility matrix

Status values: `VERIFIED`, `TESTED`, `PARTIAL`, `UNSUPPORTED`, and `BLOCKED`.

| Area | Status | Evidence / limitation |
| --- | --- | --- |
| ELF64 x86-64 header validation | VERIFIED | Windows ELF reader against emulator `libc.so` |
| PT_LOAD reservation and protection | VERIFIED | `build-and-test-windows.sh` |
| PT_TLS discovery and dynamic guest blocks | TESTED | Windows TLS backend tests and Q fixture |
| Static/initial-exec TLS in prebuilt Windows-loaded ELF | PARTIAL | Rejected explicitly; Android `libc.so` requires this path |
| `R_X86_64_RELATIVE`, absolute, PC-relative, PLT | VERIFIED | `x86_64_relocation_test` and Q runtime fixture |
| GOTPCREL/GOTPCRELX/REX_GOTPCRELX | VERIFIED | Linux and native Windows relocation tests |
| `R_X86_64_GOTTPOFF` arithmetic | TESTED | Primitive tests; executable IE guest access remains incomplete |
| TLSGD/TLSLD | VERIFIED | NDK-generated global/local-dynamic fixtures; native Windows two-thread smoke |
| TLSDESC | UNSUPPORTED | No x86-64 descriptor resolver path yet |
| Android APS2 valid streams | VERIFIED | `packed_reloc_test` and real Linux smoke |
| Android APS2 malformed streams | VERIFIED | Checked decoder and negative regression tests |
| Symbol version definitions/requirements | TESTED | Emulator `libc.so` parsing and Windows ABI fix |
| Constructors/destructors | VERIFIED | Windows Q fixture runtime smoke |
| IFUNC resolution | VERIFIED | Windows Q fixture runtime smoke |
| `android_dlopen`/`android_dlsym`/`android_dlclose` | TESTED | Linux real-rootfs and Windows fixture smoke |
| `dladdr` | VERIFIED | Native Windows Q fixture resolves its exported function address |
| `dlvsym` | TESTED | Native Windows Q fixture exercises missing-symbol failure path; versioned-symbol semantics remain limited |
| `dl_iterate_phdr` | VERIFIED | Native Windows Q fixture enumerates loaded program headers |
| Namespaces and search paths | TESTED | Q source and fixture path coverage; broader graph coverage pending |
| Typed SysV/Microsoft x64 calls | TESTED | ABI thunk suite covers mixed scalars, pair returns, callbacks, and repeated stack-preservation checks; >4-argument stack placement is not exposed |
| Arbitrary variadic forwarding | UNSUPPORTED | No safe generic bridge |
| Windows FLS guest TLS backend | VERIFIED | Backend unit tests and Q runtime fixture |
| Bionic properties on Windows | TESTED | Environment-backed implementation |
| Shared memory hooks | UNSUPPORTED | Explicit `ENOSYS` paths |
| JNI / ART | BLOCKED | Requires ART/JNI runtime and Android framework dependencies |
| Binder | BLOCKED | Requires Binder transport and Android services |
| Graphics / media / HAL providers | BLOCKED | Requires target-specific external providers |
| Real Android `libm.so` load and `cos(0)` execution on Linux | VERIFIED | Emulator API 35 x86-64 rootfs |
| Real Android `libz.so` load and `crc32("hello")` execution on Linux | VERIFIED | Emulator API 35 x86-64 rootfs |
| Repeated Q fixture load/unload lifetime | VERIFIED | Native Windows 8-iteration smoke and missing-library failure cleanup |
| Real Android `libc.so` Windows execution | BLOCKED | Requires guest static TLS access support |

The matrix is intentionally conservative: parsing a library or resolving one
symbol is not counted as functional support for the whole library.
