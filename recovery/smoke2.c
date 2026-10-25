/* smoke2.c — reconstructed DRM init harness for the libhybris-win in-process path.
 * Calls drm_lib_init() then drm_lib_get_account() against a real Android rootfs.
 * A VEH unprotects RELRO pages that the Q linker write-faults on during linking,
 * and prints diagnostics for any fatal fault. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>
#include "drm_lib.h"

extern void *android_dlopen(const char *filename, int flag);
extern void *android_dlsym(void *handle, const char *symbol);
extern const char *android_dlerror(void);
extern void hybris_set_hook_callback(void *(*cb)(const char *sym, const char *req));

/* Fault-proof read: returns 1 and fills dst on success, 0 if src is unreadable. */
static int safe_rd(void *dst, const void *src, size_t n) {
    SIZE_T got = 0;
    return ReadProcessMemory(GetCurrentProcess(), src, dst, n, &got) && got == n;
}

/* Parse the ELF image at `base` (an Android .so mapped by hybris) for its
 * DT_SONAME, so a faulting (anon) region can be named. Fault-proof; returns
 * NULL if `base` is not an ELF or the dynamic table can't be walked. */
static const char *elf_soname(unsigned char *base) {
    static char name[128];
    unsigned char id[4];
    if (!base || !safe_rd(id, base, 4) ||
        id[0] != 0x7f || id[1] != 'E' || id[2] != 'L' || id[3] != 'F')
        return NULL;
    unsigned short phnum = 0, phentsize = 0;
    unsigned long long phoff = 0;
    if (!safe_rd(&phoff, base + 0x20, 8) || !safe_rd(&phentsize, base + 0x36, 2) ||
        !safe_rd(&phnum, base + 0x38, 2) || phnum > 64)
        return NULL;
    unsigned long long dyn_vaddr = 0;
    for (unsigned short i = 0; i < phnum; i++) {
        unsigned char *ph = base + phoff + (unsigned)i * phentsize;
        unsigned int p_type = 0; unsigned long long p_vaddr = 0;
        if (!safe_rd(&p_type, ph, 4) || !safe_rd(&p_vaddr, ph + 0x10, 8)) break;
        if (p_type == 2 /*PT_DYNAMIC*/) { dyn_vaddr = p_vaddr; break; }
    }
    if (!dyn_vaddr) return NULL;
    unsigned long long strtab = 0, soname_off = (unsigned long long)-1;
    for (int i = 0; i < 512; i++) {
        unsigned long long d[2];
        if (!safe_rd(d, base + dyn_vaddr + (size_t)i * 16, 16) || d[0] == 0) break;
        if (d[0] == 5 /*DT_STRTAB*/) strtab = d[1];
        if (d[0] == 14 /*DT_SONAME*/) soname_off = d[1];
    }
    if (strtab == 0 || soname_off == (unsigned long long)-1) return NULL;
    unsigned char *s = (strtab > (unsigned long long)base) ? (unsigned char *)strtab
                                                           : base + strtab;
    if (!safe_rd(name, s + soname_off, sizeof(name))) return NULL;
    name[sizeof(name) - 1] = '\0';
    return name;
}

static const char *modname(void *addr) {
    static char buf[64];
    HMODULE h = NULL;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)addr, &h) && h) {
        char path[MAX_PATH];
        if (GetModuleFileNameA(h, path, sizeof(path))) {
            const char *b = strrchr(path, '\\');
            snprintf(buf, sizeof(buf), "%s", b ? b + 1 : path);
            return buf;
        }
    }
    return "(anon)";
}

static LONG WINAPI crash_veh(EXCEPTION_POINTERS *ep) {
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    /* RELRO workaround: the Q linker marks GOT/.data.rel.ro read-only, then a
     * relocation or constructor writes to it. Unprotect the page and continue. */
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2 &&
        er->ExceptionInformation[0] == 1 /* write */) {
        void *addr = (void *)er->ExceptionInformation[1];
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READONLY || mbi.Protect == PAGE_EXECUTE_READ ||
             mbi.Protect == PAGE_NOACCESS)) {
            void *page = (void *)((uintptr_t)addr & ~(uintptr_t)0xFFF);
            DWORD old;
            if (VirtualProtect(page, 0x2000, PAGE_EXECUTE_READWRITE, &old))
                return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    if (er->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
        er->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION &&
        er->ExceptionCode != EXCEPTION_PRIV_INSTRUCTION &&
        er->ExceptionCode != EXCEPTION_STACK_OVERFLOW)
        return EXCEPTION_CONTINUE_SEARCH;

    static LONG crash_count = 0;
    if (InterlockedIncrement(&crash_count) > 1) return EXCEPTION_CONTINUE_SEARCH;

    fprintf(stderr, "\n*** CRASH code=0x%08lx at RIP=%p tid=%lu\n",
            er->ExceptionCode, er->ExceptionAddress, GetCurrentThreadId());
    if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er->NumberParameters >= 2)
        fprintf(stderr, "    %s addr=%p\n",
                er->ExceptionInformation[0] ? "WRITE" : "READ",
                (void *)er->ExceptionInformation[1]);
    {
        CONTEXT *c = ep->ContextRecord;
        fprintf(stderr, "    rax=%016llx rcx=%016llx rdx=%016llx rsi=%016llx\n",
                (unsigned long long)c->Rax, (unsigned long long)c->Rcx,
                (unsigned long long)c->Rdx, (unsigned long long)c->Rsi);
        fprintf(stderr, "    r8 =%016llx r9 =%016llx rbx=%016llx rsp=%016llx\n",
                (unsigned long long)c->R8, (unsigned long long)c->R9,
                (unsigned long long)c->Rbx, (unsigned long long)c->Rsp);
    }
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(er->ExceptionAddress, &mbi, sizeof(mbi))) {
            const char *so = elf_soname((unsigned char *)mbi.AllocationBase);
            fprintf(stderr, "    -> in %s [%s] AllocBase=%p off=0x%llx\n",
                    modname(er->ExceptionAddress), so ? so : "?",
                    mbi.AllocationBase,
                    (unsigned long long)((uintptr_t)er->ExceptionAddress -
                                         (uintptr_t)mbi.AllocationBase));
        }
    }
    {
        /* Dump a window [RIP-64, RIP+32) so we can see how control flow reached
         * RIP (fall-through vs jump). Make both pages readable first. */
        uintptr_t rip = (uintptr_t)er->ExceptionAddress;
        void *pg0 = (void *)((rip - 64) & ~(uintptr_t)0xFFF);
        DWORD old0 = 0, old1 = 0;
        VirtualProtect(pg0, 0x1000, PAGE_EXECUTE_READWRITE, &old0);
        VirtualProtect((void *)(((rip + 32) & ~(uintptr_t)0xFFF)), 0x1000, PAGE_EXECUTE_READWRITE, &old1);
        unsigned char b[96]; SIZE_T nr = 0;
        ReadProcessMemory(GetCurrentProcess(), (void *)(rip - 64), b, sizeof(b), &nr);
        fprintf(stderr, "    code window [RIP-64 .. RIP+32) (%llu bytes), RIP at offset 64:\n",
                (unsigned long long)nr);
        for (SIZE_T i = 0; i < nr; i += 16) {
            fprintf(stderr, "      %+4d:", (int)i - 64);
            for (SIZE_T j = i; j < i + 16 && j < nr; j++)
                fprintf(stderr, " %s%02x", (j == 64) ? ">" : "", b[j]);
            fprintf(stderr, "\n");
        }
    }
    {
        /* The faulting region has no unwind data, so RtlCaptureStackBackTrace
         * can't find the caller. Dump stack qwords and flag any that point into
         * a mapped region (the bad call's return address is among them). */
        unsigned long long *sp = (unsigned long long *)ep->ContextRecord->Rsp;
        fprintf(stderr, "    stack words @rsp:\n");
        for (int i = 0; i < 40; i++) {
            unsigned long long v = 0;
            if (!safe_rd(&v, sp + i, 8)) continue;
            MEMORY_BASIC_INFORMATION mbi;
            if (v > 0x10000 && VirtualQuery((void *)v, &mbi, sizeof(mbi)) &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
                const char *so = elf_soname((unsigned char *)mbi.AllocationBase);
                fprintf(stderr, "      [rsp+0x%02x]=%016llx  %-14s [%s] base=%p off=0x%llx\n",
                        i * 8, v, modname((void *)v), so ? so : "?",
                        mbi.AllocationBase,
                        (unsigned long long)(v - (uintptr_t)mbi.AllocationBase));
            }
        }
    }
    {
        void *frames[20];
        USHORT n = RtlCaptureStackBackTrace(0, 20, frames, NULL);
        fprintf(stderr, "    stack (%u frames):\n", n);
        for (USHORT i = 0; i < n; i++) {
            MEMORY_BASIC_INFORMATION mbi;
            const char *who = "(anon)";
            unsigned long long off = 0;
            if (VirtualQuery(frames[i], &mbi, sizeof(mbi))) {
                who = modname(frames[i]);
                const char *so = elf_soname((unsigned char *)mbi.AllocationBase);
                off = (unsigned long long)((uintptr_t)frames[i] - (uintptr_t)mbi.AllocationBase);
                fprintf(stderr, "      [%2u] %p  %-14s [%s] off=0x%llx\n",
                        i, frames[i], who, so ? so : "?", off);
            } else {
                fprintf(stderr, "      [%2u] %p  ?\n", i, frames[i]);
            }
        }
    }
    fflush(stderr);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void *hook_cb(const char *sym, const char *req) {
    (void)req;
    if (!sym) return NULL;
    if (!strcmp(sym, "dlopen"))  return (void *)android_dlopen;
    if (!strcmp(sym, "dlsym"))   return (void *)android_dlsym;
    if (!strcmp(sym, "dlerror")) return (void *)android_dlerror;
    return NULL;
}

static void state_cb(const char *state, void *ud) {
    (void)ud;
    fprintf(stderr, "[state] -> %s\n", state ? state : "(null)");
    fflush(stderr);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    fprintf(stderr, "[smoke2] VERSION=stackdump-v1\n");
    AddVectoredExceptionHandler(1, crash_veh);

    char linker_dir[MAX_PATH] = "C:\\storage\\hybris-linker";
    char rootfs[MAX_PATH]     = "C:\\rootfs\\system\\lib64";
    char base_dir[MAX_PATH]   = "C:\\Users\\Podman\\drm_files";
    if (argc > 1) strncpy(linker_dir, argv[1], sizeof(linker_dir) - 1);
    if (argc > 2) strncpy(rootfs,     argv[2], sizeof(rootfs) - 1);
    if (argc > 3) strncpy(base_dir,   argv[3], sizeof(base_dir) - 1);

    SetEnvironmentVariableA("HYBRIS_LINKER_DIR",      linker_dir);
    SetEnvironmentVariableA("HYBRIS_LD_LIBRARY_PATH", rootfs);
    SetEnvironmentVariableA("ADAM_DRM_DEBUG",         "1");

    printf("[smoke2] linker_dir=%s\n[smoke2] rootfs=%s\n[smoke2] base_dir=%s\n",
           linker_dir, rootfs, base_dir);
    hybris_set_hook_callback(hook_cb);
    printf("[smoke2] hook callback registered\n");

    drm_lib_config_t cfg = {0};
    cfg.base_dir  = base_dir;
    cfg.lib64_dir = rootfs;
    cfg.state_cb  = state_cb;

    printf("[smoke2] calling drm_lib_init...\n"); fflush(stdout);
    int rc = drm_lib_init(&cfg);
    if (rc != 0) { printf("INIT_FAIL rc=%d\n", rc); return 1; }
    printf("INIT_OK\n"); fflush(stdout);

    char *acct = drm_lib_get_account();
    if (!acct) { printf("ACCOUNT_FAIL\n"); drm_lib_shutdown(); return 1; }
    printf("ACCOUNT_OK: %.120s\n", acct);
    free(acct);
    drm_lib_shutdown();
    printf("SHUTDOWN_OK\n");
    return 0;
}
