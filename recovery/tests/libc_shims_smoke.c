/* Windows smoke test for hybris/common/windows_libc_shims.h.
 * Loads libhybris-core.dll, resolves shims through hybris_get_hooked_symbol the
 * way the loader does, and calls them with the System V ABI.
 * Build/run from an MSYS2 UCRT64 shell with the DLL beside the exe:
 *   gcc -O1 -o libc_shims_smoke.exe libc_shims_smoke.c && ./libc_shims_smoke.exe
 */
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>

#define SYSV __attribute__((sysv_abi))
typedef void *(*resolver_t)(const char *, const char *);
static resolver_t resolve;
static int g_fail, g_n;

#define CHECK(cond, what) do { g_n++; if (!(cond)) { g_fail++; printf("FAIL  %s\n", what); } } while (0)

static void *R(const char *name)
{
    void *f = resolve(name, "smoke");
    if (!f) { g_n++; g_fail++; printf("FAIL  %s is not hooked\n", name); }
    return f;
}

int main(void)
{
    HMODULE m = LoadLibraryA("libhybris-core.dll");
    if (!m) { printf("cannot load libhybris-core.dll (%lu)\n", GetLastError()); return 2; }
    resolve = (resolver_t)GetProcAddress(m, "hybris_get_hooked_symbol");
    if (!resolve) { printf("hybris_get_hooked_symbol not exported\n"); return 2; }

    char buf[128];

    /* formatted output */
    int (SYSV *snp)(char *, size_t, const char *, ...) = R("snprintf");
    int (SYSV *spf)(char *, const char *, ...) = R("sprintf");
    if (snp) { int r = snp(buf, sizeof buf, "%s-%d-%.2f-%lld-%5x|%-4s|", "a", 42, 1.5, 123456789012LL, 255, "z");
               CHECK(r == 34 && !strcmp(buf, "a-42-1.50-123456789012-   ff|z   |"), "snprintf formats SysV args"); }
    if (spf) { spf(buf, "%d/%d/%s", 1, 2, "three"); CHECK(!strcmp(buf, "1/2/three"), "sprintf writes the buffer"); }
    if (snp) { int r = snp(buf, 5, "%s", "0123456789"); CHECK(r == 10 && !strcmp(buf, "0123"), "snprintf truncates, returns full length"); }

    /* identity and system information */
    int (SYSV *getpid_)(void) = R("getpid");
    int (SYSV *gettid_)(void) = R("gettid");
    int64_t (SYSV *sysconf_)(int) = R("sysconf");
    int (SYSV *gtod)(int64_t *, void *) = R("gettimeofday");
    int (SYSV *getrlimit_)(int, uint64_t *) = R("getrlimit");
    int (SYSV *sysinfo_)(void *) = R("sysinfo");
    int (SYSV *ghn)(char *, size_t) = R("gethostname");
    if (getpid_) CHECK(getpid_() == (int)GetCurrentProcessId(), "getpid");
    if (gettid_) CHECK(gettid_() == (int)GetCurrentThreadId(), "gettid");
    if (sysconf_) { CHECK(sysconf_(0x27) == 4096, "sysconf(PAGESIZE)"); CHECK(sysconf_(0x61) >= 1, "sysconf(NPROCESSORS_ONLN)");
                    CHECK(sysconf_(0x62) > 0, "sysconf(PHYS_PAGES)"); CHECK(sysconf_(0x9999) == -1 && errno == 22, "sysconf(unknown) -> EINVAL"); }
    if (gtod) { int64_t tv[2]; time_t now = time(NULL); CHECK(gtod(tv, NULL) == 0 && tv[0] >= now - 2 && tv[0] <= now + 2 && tv[1] >= 0 && tv[1] < 1000000, "gettimeofday"); }
    if (getrlimit_) { uint64_t r[2]; CHECK(getrlimit_(7, r) == 0 && r[0] == 4096, "getrlimit(NOFILE)"); }
    if (sysinfo_) { struct { int64_t up; uint64_t l[3]; uint64_t total; } si; CHECK(sysinfo_(&si) == 0 && si.total > 0, "sysinfo totalram"); }
    if (ghn) { char h[64]; CHECK(ghn(h, sizeof h) == 0 && h[0], "gethostname"); }

    /* pipes, dup, writev */
    int (SYSV *pipe2_)(int *, int) = R("pipe2");
    int (SYSV *dup_)(int) = R("dup");
    int64_t (SYSV *writev_)(int, const void *, int) = R("writev");
    int64_t (SYSV *rd)(int, void *, size_t) = R("read");
    int (SYSV *cl)(int) = R("close");
    if (pipe2_ && dup_ && writev_ && rd && cl) {
        int fds[2]; struct { const void *b; size_t n; } iov[2] = { { "ab", 2 }, { "cde", 3 } };
        CHECK(pipe2_(fds, 0) == 0, "pipe2");
        CHECK(writev_(fds[1], iov, 2) == 5, "writev gathers 5 bytes");
        int d = dup_(fds[0]); CHECK(d >= 0 && d != fds[0], "dup");
        memset(buf, 0, 8); CHECK(rd(d, buf, 5) == 5 && !memcmp(buf, "abcde", 5), "read through dup'd pipe");
        cl(d); cl(fds[0]); cl(fds[1]);
    }

    /* files: *at calls, truncate, statfs, flock, fallocate */
    char dir[MAX_PATH], a[MAX_PATH], b[MAX_PATH];
    GetTempPathA(sizeof dir, dir);
    snprintf(a, sizeof a, "%shybris_smoke_a.txt", dir); snprintf(b, sizeof b, "%shybris_smoke_b.txt", dir);
    FILE *f = fopen(a, "wb"); if (f) { fputs("0123456789", f); fclose(f); }
    int (SYSV *facc)(int, const char *, int, int) = R("faccessat");
    int (SYSV *fst)(int, const char *, void *, int) = R("fstatat");
    int (SYSV *tr)(const char *, int64_t) = R("truncate");
    int (SYSV *ren)(int, const char *, int, const char *) = R("renameat");
    int (SYSV *unl)(int, const char *, int) = R("unlinkat");
    int (SYSV *sfs)(const char *, void *) = R("statfs");
    int (SYSV *flk)(int, int) = R("flock");
    int (SYSV *fal)(int, int, int64_t, int64_t) = R("fallocate");
    if (facc) { CHECK(facc(-100, a, 0, 0) == 0, "faccessat(AT_FDCWD) existing"); CHECK(facc(-100, "C:/no/such/file", 0, 0) != 0, "faccessat missing"); }
    if (facc) { errno = 0; CHECK(facc(7, "relative.txt", 0, 0) == -1 && errno == 9, "faccessat relative+dirfd -> EBADF"); }
    if (tr) { struct _stat64 st; CHECK(tr(a, 4) == 0 && _stat64(a, &st) == 0 && st.st_size == 4, "truncate shrinks to 4"); errno = 0; CHECK(tr("C:/no/such/file", 0) == -1 && errno == 2, "truncate missing -> ENOENT"); }
    if (fst) { char st[256]; CHECK(fst(-100, a, st, 0) == 0, "fstatat existing"); }
    if (ren) { CHECK(ren(-100, a, -100, b) == 0 && _access(b, 0) == 0 && _access(a, 0) != 0, "renameat moves file"); }
    if (sfs) { struct { int64_t type, bsize; uint64_t blocks; } s; CHECK(sfs("C:/", &s) == 0 && s.bsize == 4096 && s.blocks > 0, "statfs"); }
    if (flk) CHECK(flk(3, 2) == 0, "flock grants lock");
    if (fal) { int fd = _open(b, _O_RDWR | _O_BINARY); struct _stat64 st; CHECK(fd >= 0 && fal(fd, 0, 0, 100) == 0 && _stat64(b, &st) == 0 && st.st_size == 100, "fallocate extends to 100"); if (fd >= 0) _close(fd); }
    if (unl) { CHECK(unl(-100, b, 0) == 0 && _access(b, 0) != 0, "unlinkat removes file"); }

    /* processes and signals */
    int (SYSV *kill_)(int, int) = R("kill");
    int64_t (SYSV *fork_)(void) = R("fork");
    int (SYSV *sigact)(int, const void *, void *) = R("sigaction");
    if (kill_) { CHECK(kill_((int)GetCurrentProcessId(), 0) == 0, "kill(self,0)"); errno = 0; CHECK(kill_(999999, 0) == -1 && errno == 3, "kill(other,0) -> ESRCH"); }
    if (fork_) { errno = 0; CHECK(fork_() == -1 && errno == 38, "fork -> ENOSYS"); }
    if (sigact) { char old[32]; memset(old, 0xAA, sizeof old); CHECK(sigact(15, NULL, old) == 0 && old[0] == 0 && old[31] == 0, "sigaction zeroes oldact"); }

    /* misc */
    void (SYSV *a4)(void *, size_t) = R("arc4random_buf");
    if (a4) { unsigned char r[32]; memset(r, 0, sizeof r); a4(r, sizeof r); int nz = 0; for (int i = 0; i < 32; i++) nz |= r[i]; CHECK(nz, "arc4random_buf fills"); }
    int (SYSV *prc)(int, uint64_t, uint64_t, uint64_t, uint64_t) = R("prctl");
    if (prc) { errno = 0; CHECK(prc(15, 0, 0, 0, 0) == 0, "prctl(PR_SET_NAME)"); CHECK(prc(999, 0, 0, 0, 0) == -1 && errno == 22, "prctl(unknown) -> EINVAL"); }
    int64_t (SYSV *gaux)(uint64_t) = R("getauxval");
    if (gaux) CHECK(gaux(6) == 4096, "getauxval(AT_PAGESZ)");
    int (SYSV *gp)(const char *, char *) = R("__system_property_get");
    if (gp) { strcpy(buf, "junk"); CHECK(gp("ro.build.version.sdk", buf) == 0 && buf[0] == 0, "system property get -> empty"); }

    printf("%d checks, %d failures\n", g_n, g_fail);
    return g_fail ? 1 : 0;
}
