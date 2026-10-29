#include "windows_core_compat.h"

#include <hybris/common/hooks.h>
#include <hybris/common/dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Full hook-table resolver from hooks.c (pthread→winpthread + stdlib). */
extern void* hybris_get_hooked_symbol(const char *sym, const char *requester);

typedef void *(*android_dlopen_fn)(const char *, int);
typedef void *(*android_dlsym_fn)(void *, const char *);
typedef int (*android_dlclose_fn)(void *);
typedef char *(*android_dlerror_fn)(void);
typedef void *(*android_dlvsym_fn)(void *, const char *, const char *);
typedef int (*android_dladdr_fn)(const void *, void *);
typedef int (*android_dl_iterate_phdr_fn)(int (*)(void *, size_t, void *), void *);
typedef void (*android_linker_init_fn)(int, void *(*)(const char *, const char *), int);
typedef void *(*android_dlopen_ext_fn)(const char *, int, const void *);
typedef void (*android_get_path_fn)(char *, size_t);
typedef void (*android_update_path_fn)(const char *);

static HMODULE linker_module;
static android_dlopen_fn linker_dlopen;
static android_dlsym_fn linker_dlsym;
static android_dlclose_fn linker_dlclose;
static android_dlerror_fn linker_dlerror;
static android_dlvsym_fn linker_dlvsym;
static android_dladdr_fn linker_dladdr;
static android_dl_iterate_phdr_fn linker_dl_iterate_phdr;
static android_dlopen_ext_fn linker_dlopen_ext;
static android_get_path_fn linker_get_path;
static android_update_path_fn linker_update_path;
static char windows_dlerror[256];
/* Exposed so windows_hook_table.c can consult user-supplied fallback. */
hybris_hook_cb _hybris_win32_user_hook_cb;

static void windows_set_error(const char *message) {
    snprintf(windows_dlerror, sizeof(windows_dlerror), "%s", message);
}

static void *windows_symbol(const char *name) {
    FARPROC raw;
    void *result = NULL;
    if (linker_module == NULL) return NULL;
    raw = GetProcAddress(linker_module, name);
    memcpy(&result, &raw, sizeof(result));
    return result;
}

static LONG WINAPI _crash_report(EXCEPTION_POINTERS *ep);

static int windows_linker_init(void) {
    char path[MAX_PATH];
    const char *directory;
    android_linker_init_fn init;

    if (linker_module != NULL) return linker_dlopen != NULL ? 0 : -1;
    AddVectoredExceptionHandler(0, _crash_report);

    /* Use GetEnvironmentVariableA to read the real Windows process environment,
     * bypassing any POSIX shim (MSYS2/Cygwin getenv may return a POSIX path
     * that LoadLibraryA cannot resolve). */
    {
        static char env_dir[MAX_PATH];
        DWORD n = GetEnvironmentVariableA("HYBRIS_LINKER_DIR", env_dir, sizeof(env_dir));
        directory = (n > 0 && n < sizeof(env_dir)) ? env_dir : NULL;
    }
    if (directory == NULL || directory[0] == '\0') directory = ".";
    snprintf(path, sizeof(path), "%s/q.so", directory);
    linker_module = LoadLibraryA(path);
    if (linker_module == NULL) {
        snprintf(windows_dlerror, sizeof(windows_dlerror),
                 "LoadLibraryA(%s) failed (%lu)", path,
                 (unsigned long)GetLastError());
        return -1;
    }

    linker_dlopen = (android_dlopen_fn)windows_symbol("android_dlopen");
    linker_dlsym = (android_dlsym_fn)windows_symbol("android_dlsym");
    linker_dlclose = (android_dlclose_fn)windows_symbol("android_dlclose");
    linker_dlerror = (android_dlerror_fn)windows_symbol("android_dlerror");
    linker_dlvsym = (android_dlvsym_fn)windows_symbol("android_dlvsym");
    linker_dladdr = (android_dladdr_fn)windows_symbol("android_dladdr");
    linker_dl_iterate_phdr =
        (android_dl_iterate_phdr_fn)windows_symbol("android_dl_iterate_phdr");
    linker_dlopen_ext = (android_dlopen_ext_fn)windows_symbol("android_dlopen_ext");
    linker_get_path = (android_get_path_fn)windows_symbol("android_get_LD_LIBRARY_PATH");
    linker_update_path = (android_update_path_fn)windows_symbol("android_update_LD_LIBRARY_PATH");
    init = (android_linker_init_fn)windows_symbol("android_linker_init");
    if (linker_dlopen == NULL || linker_dlsym == NULL || linker_dlclose == NULL ||
        linker_dlerror == NULL || init == NULL) {
        windows_set_error("Q linker exports are incomplete");
        return -1;
    }

    /* Use the full hook table (hooks.c) as the primary symbol resolver so
     * Android's pthread_* calls are mapped to MinGW winpthread rather than
     * bionic's futex-based implementation.  The user-supplied hook_callback
     * (set via hybris_set_hook_callback) is consulted as a fallback inside
     * hybris_get_hooked_symbol for any symbols not in the built-in table. */
    init(29, hybris_get_hooked_symbol, 0);
    return 0;
}

/* Names an address through the Q linker's dladdr: "lib.so+0xoff (symbol+0xoff)", or "" when it is in no guest library. */
static void _crash_where(unsigned long long v, char *out, size_t cap)
{
    struct { const char *fname; void *fbase; const char *sname; void *saddr; } info;
    out[0] = 0;
    if (!linker_dladdr) return;
    memset(&info, 0, sizeof info);
    if (!linker_dladdr((const void *)(uintptr_t)v, &info) || !info.fname) return;
    const char *b = strrchr(info.fname, '/');
    b = b ? b + 1 : info.fname;
    if (info.sname && info.saddr)
        snprintf(out, cap, " <%s+0x%llx (%s+0x%llx)>", b, v - (unsigned long long)(uintptr_t)info.fbase, info.sname,
                 v - (unsigned long long)(uintptr_t)info.saddr);
    else
        snprintf(out, cap, " <%s+0x%llx>", b, v - (unsigned long long)(uintptr_t)info.fbase);
}

/* Log-only crash report for faults nothing else handled (guest code has no unwind data, so the
 * process otherwise just dies with 0xC0000005 and no clue where). Runs last in the chain and
 * never handles the exception. Skipped for faults inside the host executable (Go's own). */
static LONG WINAPI _crash_report(EXCEPTION_POINTERS *ep) {
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    const DWORD code = er->ExceptionCode;
    const int memfault = code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_ILLEGAL_INSTRUCTION ||
                         code == EXCEPTION_PRIV_INSTRUCTION || code == EXCEPTION_STACK_OVERFLOW;
    /* Other process-killing codes (invalid handle, heap corruption, fast-fail, bad parameter): no module filter. */
    const int fatal = code == 0xC0000008 || code == 0xC0000374 || code == 0xC0000409 || code == 0xC000000D ||
                      code == 0xC0000094 || code == 0xC000001D || code == 0xC00000FD;
    if (!memfault && !fatal) return EXCEPTION_CONTINUE_SEARCH;
    static LONG once = 0;
    HMODULE exe = GetModuleHandleA(NULL), at = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)er->ExceptionAddress, &at);
    if ((memfault && at == exe) || InterlockedIncrement(&once) > 1) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT *c = ep->ContextRecord;
    MEMORY_BASIC_INFORMATION mbi;
    char mod[MAX_PATH] = "(anon)";
    unsigned long long base = 0;
    if (VirtualQuery(er->ExceptionAddress, &mbi, sizeof mbi)) base = (unsigned long long)(uintptr_t)mbi.AllocationBase;
    if (at) GetModuleFileNameA(at, mod, sizeof mod);
    fprintf(stderr, "[guest-crash] code=0x%08lx rip=%p tid=%lu in %s base=0x%llx off=0x%llx\n",
            er->ExceptionCode, er->ExceptionAddress, GetCurrentThreadId(), mod, base,
            (unsigned long long)(uintptr_t)er->ExceptionAddress - base);
    { char w[512]; _crash_where((unsigned long long)(uintptr_t)er->ExceptionAddress, w, sizeof w);
      fprintf(stderr, "[guest-crash] rip is%s\n", w[0] ? w : " in no guest library"); }
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
        fprintf(stderr, "[guest-crash] %s addr=%p\n", er->ExceptionInformation[0] ? "write" : "read",
                (void *)er->ExceptionInformation[1]);
    fprintf(stderr, "[guest-crash] rax=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx r8=%llx r9=%llx rsp=%llx\n",
            (unsigned long long)c->Rax, (unsigned long long)c->Rcx, (unsigned long long)c->Rdx,
            (unsigned long long)c->Rsi, (unsigned long long)c->Rdi, (unsigned long long)c->R8,
            (unsigned long long)c->R9, (unsigned long long)c->Rsp);
    {   /* Real unwind of the faulting thread (host frames have unwind data; guest frames end the walk). */
        void *frames[32];
        USHORT nf = RtlCaptureStackBackTrace(0, 32, frames, NULL);
        for (USHORT i = 0; i < nf; i++) {
            char m[MAX_PATH] = "(anon)", w[512]; HMODULE h = NULL; MEMORY_BASIC_INFORMATION q;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)frames[i], &h) && h) {
                GetModuleFileNameA(h, m, sizeof m);
                const char *bn = strrchr(m, '\\'); if (bn) memmove(m, bn + 1, strlen(bn));
            }
            unsigned long long off = 0;
            if (VirtualQuery(frames[i], &q, sizeof q)) off = (unsigned long long)((uintptr_t)frames[i] - (uintptr_t)q.AllocationBase);
            _crash_where((unsigned long long)(uintptr_t)frames[i], w, sizeof w);
            fprintf(stderr, "[guest-crash] bt[%u] %p %s+0x%llx%s\n", i, frames[i], m, off, w);
        }
    }
    /* No unwind data: list every stack word that points into executable memory. */
    unsigned long long *sp = (unsigned long long *)c->Rsp;
    for (int i = 0; i < 64; i++) {
        unsigned long long v;
        if (!VirtualQuery(sp + i, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS)) break;
        v = sp[i];
        if (v > 0x10000 && VirtualQuery((void *)v, &mbi, sizeof mbi) && mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            char m[MAX_PATH] = "(anon)";
            HMODULE h = NULL;
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                   (LPCSTR)v, &h) && h)
                GetModuleFileNameA(h, m, sizeof m);
            char w[512]; _crash_where(v, w, sizeof w);
            fprintf(stderr, "[guest-crash]   [rsp+0x%02x]=%llx %s base=0x%llx off=0x%llx%s\n", i * 8, v, m,
                    (unsigned long long)(uintptr_t)mbi.AllocationBase,
                    v - (unsigned long long)(uintptr_t)mbi.AllocationBase, w);
        }
    }
    fflush(stderr);
    return EXCEPTION_CONTINUE_SEARCH;
}

void hybris_set_hook_callback(hybris_hook_cb callback) {
    _hybris_win32_user_hook_cb = callback;
}

void *android_dlopen(const char *filename, int flag) {
    if (windows_linker_init() != 0) return NULL;
    return linker_dlopen(filename, flag);
}

char *android_dlerror(void) {
    if (linker_dlerror != NULL) return linker_dlerror();
    return windows_dlerror[0] != '\0' ? windows_dlerror : NULL;
}

void *android_dlsym(void *handle, const char *symbol) {
    if (windows_linker_init() != 0) return NULL;
    return linker_dlsym(handle, symbol);
}

int android_dlclose(void *handle) {
    if (windows_linker_init() != 0) return -1;
    return linker_dlclose(handle);
}

void *android_dlvsym(void *handle, const char *symbol, const char *version) {
    if (windows_linker_init() != 0 || linker_dlvsym == NULL) return NULL;
    return linker_dlvsym(handle, symbol, version);
}

int android_dladdr(const void *addr, void *info) {
    if (windows_linker_init() != 0 || linker_dladdr == NULL) {
        errno = ENOSYS;
        return 0;
    }
    return linker_dladdr(addr, info);
}

int android_dl_iterate_phdr(int (*callback)(void *, size_t, void *), void *data) {
    if (windows_linker_init() != 0 || linker_dl_iterate_phdr == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return linker_dl_iterate_phdr(callback, data);
}

void *android_dlopen_ext(const char *filename, int flag, const void *extinfo) {
    if (windows_linker_init() != 0 || linker_dlopen_ext == NULL) return NULL;
    return linker_dlopen_ext(filename, flag, extinfo);
}

void android_get_LD_LIBRARY_PATH(char *buffer, size_t buffer_size) {
    if (windows_linker_init() == 0 && linker_get_path != NULL)
        linker_get_path(buffer, buffer_size);
}

void android_update_LD_LIBRARY_PATH(const char *path) {
    if (windows_linker_init() == 0 && linker_update_path != NULL)
        linker_update_path(path);
}

void *hybris_dlopen(const char *filename, int flag) { return android_dlopen(filename, flag); }
void *hybris_dlsym(void *handle, const char *symbol) { return android_dlsym(handle, symbol); }
int hybris_dlclose(void *handle) { return android_dlclose(handle); }
char *hybris_dlerror(void) { return android_dlerror(); }
int hybris_dladdr(const void *addr, void *info) {
    return android_dladdr(addr, info);
}
