#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

using android_dlopen_fn = void* (*)(const char*, int);
using android_dlsym_fn = void* (*)(void*, const char*);
using android_dlclose_fn = int (*)(void*);
using android_dlerror_fn = char* (*)();
using android_dlvsym_fn = void* (*)(void*, const char*, const char*);
struct guest_dl_info {
    const char* dli_fname;
    void* dli_fbase;
    const char* dli_sname;
    void* dli_saddr;
};
using android_dladdr_fn = int (*)(const void*, guest_dl_info*);
using android_dl_iterate_phdr_fn = int (*)(int (*)(void*, size_t, void*), void*);
using android_linker_init_fn = void (*)(int, void* (*)(const char*, const char*), int);
using int_fn = int (*)();
using uintptr_fn = uintptr_t (*)();
#if defined(_WIN32) && (defined(__GNUC__) || defined(__clang__))
typedef int (*elf_int_fn)() __attribute__((sysv_abi));
typedef int (*elf_tls_value_fn)(const int*) __attribute__((sysv_abi));
typedef uintptr_t (*elf_uintptr_fn)() __attribute__((sysv_abi));
#else
using elf_int_fn = int_fn;
using elf_tls_value_fn = int (*)(const int*);
using elf_uintptr_fn = uintptr_fn;
#endif

static int fail(const char* message, android_dlerror_fn error = nullptr) {
    std::fprintf(stderr, "FAIL: %s%s%s\n", message,
                 error != nullptr && error() != nullptr ? ": " : "",
                 error != nullptr && error() != nullptr ? error() : "");
    return 1;
}

static int count_phdrs(void*, size_t, void* data) {
    ++*static_cast<int*>(data);
    return 0;
}

template <typename T>
static T symbol(void* handle, android_dlsym_fn dlsym, const char* name) {
    return reinterpret_cast<T>(dlsym(handle, name));
}

template <typename T>
static T proc(HMODULE module, const char* name) {
    FARPROC raw = GetProcAddress(module, name);
    T result = nullptr;
    static_assert(sizeof(result) == sizeof(raw), "unexpected function pointer size");
    std::memcpy(&result, &raw, sizeof(result));
    return result;
}

int main(int argc, char** argv) {
    if (argc != 3) return fail("usage: windows_q_runtime_smoke <q.dll> <fixture.so>");
    std::printf("[1] loading Q linker: %s\n", argv[1]);
    std::fflush(stdout);
    HMODULE q = LoadLibraryA(argv[1]);
    std::printf("[2] Q linker loaded: %p\n", static_cast<void*>(q));
    std::fflush(stdout);
    if (q == nullptr) return fail("LoadLibrary(q.so)");

    auto dlopen = proc<android_dlopen_fn>(q, "android_dlopen");
    auto dlsym = proc<android_dlsym_fn>(q, "android_dlsym");
    auto dlclose = proc<android_dlclose_fn>(q, "android_dlclose");
    auto dlerror = proc<android_dlerror_fn>(q, "android_dlerror");
    auto dlvsym = proc<android_dlvsym_fn>(q, "android_dlvsym");
    auto dladdr = proc<android_dladdr_fn>(q, "android_dladdr");
    auto dl_iterate_phdr = proc<android_dl_iterate_phdr_fn>(q, "android_dl_iterate_phdr");
    auto linker_init = proc<android_linker_init_fn>(q, "android_linker_init");
    std::printf("[3] exports resolved\n");
    std::fflush(stdout);
    if (dlopen == nullptr || dlsym == nullptr || dlclose == nullptr || dlerror == nullptr ||
        linker_init == nullptr) {
        return fail("Q linker exports are missing");
    }
    linker_init(29, nullptr, 0);
    std::printf("[3b] Q linker initialized\n");
    std::fflush(stdout);

    std::printf("[4] loading fixture repeatedly: %s\n", argv[2]);
    std::fflush(stdout);
    for (int iteration = 0; iteration < 8; ++iteration) {
        void* fixture = dlopen(argv[2], 2 /* RTLD_NOW */);
        if (fixture == nullptr) return fail("android_dlopen", dlerror);
        auto constructor_ran = symbol<elf_int_fn>(fixture, dlsym, "hybris_fixture_constructor_ran");
        auto tls_value = symbol<elf_tls_value_fn>(fixture, dlsym, "hybris_fixture_tls_value");
        auto tls = symbol<int*>(fixture, dlsym, "hybris_fixture_tls");
        auto dependency_value = symbol<elf_int_fn>(fixture, dlsym, "hybris_fixture_dependency_value_from_main");
        auto ifunc = symbol<elf_uintptr_fn>(fixture, dlsym, "hybris_fixture_ifunc");
        if (constructor_ran == nullptr || tls_value == nullptr || tls == nullptr ||
            dependency_value == nullptr || ifunc == nullptr) {
            return fail("android_dlsym", dlerror);
        }

        guest_dl_info info = {};
        if (dladdr == nullptr || dladdr(reinterpret_cast<const void*>(constructor_ran), &info) != 1 ||
            info.dli_fname == nullptr) {
            return fail("android_dladdr", dlerror);
        }
        int phdr_count = 0;
        if (dl_iterate_phdr == nullptr || dl_iterate_phdr(count_phdrs, &phdr_count) != 0 ||
            phdr_count == 0) {
            return fail("android_dl_iterate_phdr", dlerror);
        }
        if (dlvsym != nullptr && dlvsym(fixture, "missing_symbol", "missing") != nullptr) {
            return fail("android_dlvsym resolved a missing symbol");
        }

        if (constructor_ran() != 1) return fail("constructor did not run");
        *tls = 5 + iteration;
        if (tls_value(tls) != 5 + iteration) return fail("TLS value mismatch");
        if (dependency_value() != 37) return fail("dependency relocation mismatch");
        if (ifunc() != 42) return fail("IFUNC result mismatch");
        if (dlclose(fixture) != 0) return fail("android_dlclose", dlerror);
    }
    std::printf("PASS: Windows Q runtime load, repeated lifetime, TLS, IFUNC, loader APIs, and close\n");
    return 0;
}
