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
| TLSGD/TLSLD/TLSDESC | UNSUPPORTED | No complete linker/runtime implementation yet |
| Android APS2 valid streams | VERIFIED | `packed_reloc_test` and real Linux smoke |
| Android APS2 malformed streams | IN_PROGRESS | Hardening and negative tests are pending |
| Symbol version definitions/requirements | TESTED | Emulator `libc.so` parsing and Windows ABI fix |
| Constructors/destructors | VERIFIED | Windows Q fixture runtime smoke |
| IFUNC resolution | VERIFIED | Windows Q fixture runtime smoke |
| `android_dlopen`/`android_dlsym`/`android_dlclose` | TESTED | Linux real-rootfs and Windows fixture smoke |
| `dladdr` | PARTIAL | Linker implementation exists; Windows wrapper coverage is missing |
| `dlvsym` | PARTIAL | Q symbol path exists; end-to-end versioned-symbol test is missing |
| `dl_iterate_phdr` | PARTIAL | Internal implementation exists; Windows public-path coverage is missing |
| Namespaces and search paths | TESTED | Q source and fixture path coverage; broader graph coverage pending |
| Typed SysV/Microsoft x64 calls | TESTED | ABI thunk regression suite and Q exports |
| Arbitrary variadic forwarding | UNSUPPORTED | No safe generic bridge |
| Windows FLS guest TLS backend | VERIFIED | Backend unit tests and Q runtime fixture |
| Bionic properties on Windows | TESTED | Environment-backed implementation |
| Shared memory hooks | UNSUPPORTED | Explicit `ENOSYS` paths |
| JNI / ART | BLOCKED | Requires ART/JNI runtime and Android framework dependencies |
| Binder | BLOCKED | Requires Binder transport and Android services |
| Graphics / media / HAL providers | BLOCKED | Requires target-specific external providers |
| Real Android `libm.so` load and `cos` lookup on Linux | VERIFIED | Emulator API 35 x86-64 rootfs |
| Real Android `libc.so` Windows execution | BLOCKED | Requires guest static TLS access support |

The matrix is intentionally conservative: parsing a library or resolving one
symbol is not counted as functional support for the whole library.
