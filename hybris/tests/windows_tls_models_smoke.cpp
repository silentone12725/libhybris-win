#include <windows.h>

#include <cstdio>
#include <cstring>

using android_dlopen_fn = void* (*)(const char*, int);
using android_dlsym_fn = void* (*)(void*, const char*);
using android_dlclose_fn = int (*)(void*);
using android_dlerror_fn = char* (*)();
using android_linker_init_fn = void (*)(int, void* (*)(const char*, const char*), int);

#if defined(__GNUC__) || defined(__clang__)
typedef int (*read_fn)() __attribute__((sysv_abi));
typedef void (*write_fn)(int) __attribute__((sysv_abi));
typedef uintptr_t (*address_fn)() __attribute__((sysv_abi));
#else
using read_fn = int (*)();
using write_fn = void (*)(int);
using address_fn = uintptr_t (*)();
#endif

struct ThreadArgs {
    read_fn read;
    write_fn write;
    bool ok;
};

static DWORD WINAPI tls_thread(void* raw) {
    ThreadArgs* args = static_cast<ThreadArgs*>(raw);
    args->ok = args->read() == 7;
    args->write(19);
    args->ok = args->ok && args->read() == 19;
    return 0;
}

static int fail(const char* message, android_dlerror_fn error = nullptr) {
    const char* detail = error == nullptr ? nullptr : error();
    std::fprintf(stderr, "FAIL: %s%s%s\n", message,
                 detail == nullptr ? "" : ": ", detail == nullptr ? "" : detail);
    return 1;
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
    if (argc < 3) return fail("usage: windows_tls_models_smoke <q.so> <fixture.so>...");

    HMODULE q = LoadLibraryA(argv[1]);
    if (q == nullptr) return fail("LoadLibrary(q.so)");
    auto dlopen = proc<android_dlopen_fn>(q, "android_dlopen");
    auto dlsym = proc<android_dlsym_fn>(q, "android_dlsym");
    auto dlclose = proc<android_dlclose_fn>(q, "android_dlclose");
    auto dlerror = proc<android_dlerror_fn>(q, "android_dlerror");
    auto linker_init = proc<android_linker_init_fn>(q, "android_linker_init");
    if (dlopen == nullptr || dlsym == nullptr || dlclose == nullptr ||
        dlerror == nullptr || linker_init == nullptr) {
        return fail("Q linker exports are missing");
    }
    linker_init(29, nullptr, 0);

    for (int index = 2; index < argc; ++index) {
        void* handle = dlopen(argv[index], 2 /* RTLD_NOW */);
        if (handle == nullptr) return fail("android_dlopen", dlerror);
        auto read = symbol<read_fn>(handle, dlsym, "hybris_tls_model_read");
        auto write = symbol<write_fn>(handle, dlsym, "hybris_tls_model_write");
        auto address = symbol<address_fn>(handle, dlsym, "hybris_tls_model_address");
        if (read == nullptr || write == nullptr || address == nullptr) {
            return fail("TLS model exports missing", dlerror);
        }
        if (read() != 7 || address() == 0) return fail("TLS initializer mismatch");
        write(11);
        if (read() != 11) return fail("main-thread TLS write mismatch");

        ThreadArgs args = {read, write, false};
        HANDLE thread = CreateThread(nullptr, 0, tls_thread, &args, 0, nullptr);
        if (thread == nullptr) return fail("CreateThread");
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
        if (!args.ok) return fail("worker-thread TLS isolation mismatch");
        if (read() != 11) return fail("main-thread TLS was corrupted");
        if (dlclose(handle) != 0) return fail("android_dlclose", dlerror);
    }

    std::printf("PASS: Windows dynamic TLSGD/TLSLD models and thread isolation\n");
    return 0;
}
