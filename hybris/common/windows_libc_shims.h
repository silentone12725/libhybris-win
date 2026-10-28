/*
 * windows_libc_shims.h — Windows implementations (or loud failures) for the
 * bionic libc functions that would otherwise fall through to Android's real
 * libc.so.
 *
 * Why this exists: a guest symbol that the hook table does not claim is bound
 * to the copy in rootfs/system/lib64/libc.so.  That code performs Linux
 * system calls with a raw `syscall` instruction, which on Windows does not fail
 * cleanly: it enters the NT kernel with a Linux call number and returns garbage.
 * Static analysis of libc.so (control-flow walk from every symbol the guest
 * libraries import) found 75 such functions, plus several stdio/printf entry
 * points whose behaviour was wrong or silent.
 *
 * Policy for every function here:
 *   1. If Windows can do the job, do it (CRT / Win32), keeping Linux ABI values
 *      for errno and structure layouts.
 *   2. If it is safe to ignore (advice, no-op locks, scheduling hints), succeed
 *      and say so once.
 *   3. Otherwise fail with a Linux errno and print ONE clear line naming the
 *      function and its caller, so a missing feature never looks like random
 *      corruption.
 *
 * All entry points use the System V ABI because the caller is guest code.
 * Included by windows_hook_table.c (needs its _winpath, _sysv_* and _net_*).
 */
#ifndef HYBRIS_WINDOWS_LIBC_SHIMS_H
#define HYBRIS_WINDOWS_LIBC_SHIMS_H

#include "sysv_format.h"
#include <sys/utime.h>

#define SYSV __attribute__((sysv_abi))

/* Linux errno values (the guest compares against these, not MinGW's). */
#define LE_PERM   1
#define LE_NOENT  2
#define LE_SRCH   3
#define LE_INTR   4
#define LE_BADF   9
#define LE_CHILD  10
#define LE_AGAIN  11
#define LE_NOMEM  12
#define LE_INVAL  22
#define LE_NOTTY  25
#define LE_NOSYS  38
#define LE_NXIO   6
#define LE_OPNOTSUPP 95

#define SH_AT_FDCWD  (-100)
#define SH_AT_REMOVEDIR 0x200
#define SH_AT_SYMLINK_NOFOLLOW 0x100

/* One line per call site, once: names the function and the guest caller. */
#define SH_ONCE(name, why) do { \
    static volatile long _once; \
    if (!__atomic_exchange_n(&_once, 1, __ATOMIC_RELAXED)) { \
        fprintf(stderr, "[guest-libc] %s: %s (guest caller %p)\n", name, why, __builtin_return_address(0)); \
        fflush(stderr); } } while (0)

/* Functions that cannot work on Windows: fail loudly with a Linux errno. */
#define SH_UNSUPPORTED(name, err) \
    static int64_t SYSV _shu_##name(void) { \
        static volatile long _once; \
        if (!__atomic_exchange_n(&_once, 1, __ATOMIC_RELAXED)) { \
            fprintf(stderr, "[guest-libc] %s: not supported on Windows, failing with Linux errno %d (guest caller %p)\n", \
                    #name, (int)(err), __builtin_return_address(0)); fflush(stderr); } \
        errno = err; return -1; }

SH_UNSUPPORTED(fork,            LE_NOSYS)
SH_UNSUPPORTED(vfork,           LE_NOSYS)
SH_UNSUPPORTED(clone,           LE_NOSYS)
SH_UNSUPPORTED(execve,          LE_NOSYS)
SH_UNSUPPORTED(wait4,           LE_CHILD)
SH_UNSUPPORTED(umount2,         LE_PERM)
SH_UNSUPPORTED(pselect,         LE_NOSYS)
SH_UNSUPPORTED(inotify_init1,   LE_NOSYS)
SH_UNSUPPORTED(signalfd,        LE_NOSYS)
SH_UNSUPPORTED(sigsuspend,      LE_INTR)
SH_UNSUPPORTED(linkat,          LE_NOSYS)
SH_UNSUPPORTED(symlinkat,       LE_NOSYS)
SH_UNSUPPORTED(mknodat,         LE_NOSYS)
SH_UNSUPPORTED(fchdir,          LE_NOSYS)
SH_UNSUPPORTED(setpgid,         LE_PERM)
SH_UNSUPPORTED(setsid,          LE_PERM)
SH_UNSUPPORTED(setgroups,       LE_PERM)
SH_UNSUPPORTED(setresuid,       LE_PERM)
SH_UNSUPPORTED(setresgid,       LE_PERM)
SH_UNSUPPORTED(__res_nameinquery,   LE_NOSYS)
SH_UNSUPPORTED(__res_nsend,         LE_NOSYS)
SH_UNSUPPORTED(__res_queriesmatch,  LE_NOSYS)

/* ── formatted output (SysV va_list safe) ─────────────────────────────────── */
static int SYSV _sh_vsnprintf(char *b, size_t n, const char *fmt, sh_va ap) { return sh_vformat(b, n, fmt, ap); }
static int SYSV _sh_vsprintf(char *b, const char *fmt, sh_va ap)            { return sh_vformat(b, (size_t)-1, fmt, ap); }
static int SYSV _sh_snprintf(char *b, size_t n, const char *fmt, ...)
{ sh_va ap; __builtin_sysv_va_start(ap, fmt); int r = sh_vformat(b, n, fmt, ap); __builtin_sysv_va_end(ap); return r; }
static int SYSV _sh_sprintf(char *b, const char *fmt, ...)
{ sh_va ap; __builtin_sysv_va_start(ap, fmt); int r = sh_vformat(b, (size_t)-1, fmt, ap); __builtin_sysv_va_end(ap); return r; }

/* syslog family: there is no syslogd; route to our log so messages are not lost. */
static void SYSV _sh_vsyslog(int pri, const char *fmt, sh_va ap)
{ char buf[1024]; sh_vformat(buf, sizeof buf, fmt, ap); fprintf(stderr, "[guest-syslog] <%d> %s\n", pri, buf); fflush(stderr); }
static void SYSV _sh_syslog(int pri, const char *fmt, ...)
{ sh_va ap; __builtin_sysv_va_start(ap, fmt); _sh_vsyslog(pri, fmt, ap); __builtin_sysv_va_end(ap); }
static void SYSV _sh_openlog(const char *id, int opt, int fac) { (void)id; (void)opt; (void)fac; }
static void SYSV _sh_closelog(void) {}

/* ── fatal paths: say what happened before dying ──────────────────────────── */
static void SYSV _sh_stack_chk_fail(void)
{ fprintf(stderr, "[guest-libc] FATAL: stack smashing detected in guest code (caller %p)\n", __builtin_return_address(0)); fflush(stderr); abort(); }
static void SYSV _sh___assert2(const char *file, int line, const char *func, const char *msg)
{ fprintf(stderr, "[guest-libc] FATAL: assertion failed: %s:%d: %s: %s\n", _lowp(file) ? "?" : file, line, _lowp(func) ? "?" : func, _lowp(msg) ? "?" : msg); fflush(stderr); abort(); }
static void SYSV _sh___assert(const char *file, int line, const char *msg)
{ fprintf(stderr, "[guest-libc] FATAL: assertion failed: %s:%d: %s\n", _lowp(file) ? "?" : file, line, _lowp(msg) ? "?" : msg); fflush(stderr); abort(); }
static void SYSV _sh_android_set_abort_message(const char *msg)
{ fprintf(stderr, "[guest-libc] abort message: %s\n", _lowp(msg) ? "(null)" : msg); fflush(stderr); }
static void SYSV _sh__Exit(int code) { fflush(NULL); _exit(code); }

/* ── process identity / limits / system information ───────────────────────── */
static int  SYSV _sh_getpid(void)             { return (int)GetCurrentProcessId(); }
static int  SYSV _sh_gettid(void)             { return (int)GetCurrentThreadId(); }
static int  SYSV _sh_getuid(void)             { return 1000; }
static int  SYSV _sh_getpgid(int pid)         { (void)pid; return (int)GetCurrentProcessId(); }
static int  SYSV _sh_getpriority(int w, int who) { (void)w; (void)who; return 0; }
static int  SYSV _sh_setpriority(int w, int who, int p) { (void)w; (void)who; (void)p; SH_ONCE("setpriority", "scheduling priority hints are ignored on Windows"); return 0; }
static int  SYSV _sh_sched_ok(void)           { return 0; }
static int  SYSV _sh_sched_getparam(int pid, int *prio) { (void)pid; if (prio) *prio = 0; return 0; }
static int  SYSV _sh_umask(int m)             { static int cur = 022; int old = cur; cur = m & 0777; return old; }
static int  SYSV _sh_getpagesize(void)        { return 4096; }

static int SYSV _sh_pthread_setname_np(void *t, const char *n) { (void)t; (void)n; return 0; }
static int SYSV _sh_pthread_gettid_np(void *t)
{ return ((uintptr_t)t == (uintptr_t)pthread_self()) ? (int)GetCurrentThreadId() : 0; }
static int SYSV _sh_pthread_attr_getstack(const void *a, void **addr, size_t *sz)
{ (void)a; SH_ONCE("pthread_attr_getstack", "stack bounds are not tracked; reporting a 1 MiB unknown stack");
  if (addr) *addr = NULL; if (sz) *sz = 1u << 20; return 0; }

static int SYSV _sh_getrlimit(int res, uint64_t *r)
{
    if (!r) { errno = LE_INVAL; return -1; }
    uint64_t cur = ~0ULL, max = ~0ULL;
    switch (res) {
    case 3: cur = 8u << 20; break;               /* RLIMIT_STACK  */
    case 4: cur = 0; break;                      /* RLIMIT_CORE   */
    case 7: cur = max = 4096; break;             /* RLIMIT_NOFILE */
    default: break;
    }
    r[0] = cur; r[1] = max; return 0;
}

static int64_t SYSV _sh_sysconf(int name)
{
    MEMORYSTATUSEX ms; SYSTEM_INFO si;
    switch (name) {
    case 0x00: return 2097152;                   /* _SC_ARG_MAX */
    case 0x05: return 4096;                      /* _SC_CHILD_MAX */
    case 0x06: return 100;                       /* _SC_CLK_TCK */
    case 0x0a: return 65536;                     /* _SC_NGROUPS_MAX */
    case 0x0b: return 4096;                      /* _SC_OPEN_MAX */
    case 0x27: case 0x28: return 4096;           /* _SC_PAGESIZE / _SC_PAGE_SIZE */
    case 0x60: case 0x61:                        /* _SC_NPROCESSORS_CONF / _ONLN */
        GetSystemInfo(&si); return (int64_t)si.dwNumberOfProcessors;
    case 0x62: case 0x63:                        /* _SC_PHYS_PAGES / _SC_AVPHYS_PAGES */
        ms.dwLength = sizeof ms; GlobalMemoryStatusEx(&ms);
        return (int64_t)((name == 0x62 ? ms.ullTotalPhys : ms.ullAvailPhys) / 4096);
    default: {
        static volatile long seen[8];            /* log each unknown name once (0..255) */
        int slot = (name & 0xff) >> 5, bit = 1 << (name & 31);
        if ((name & ~0xff) == 0 && !(seen[slot] & bit)) {
            seen[slot] |= bit;
            fprintf(stderr, "[guest-libc] sysconf(0x%x): not implemented on Windows, returning -1/EINVAL (guest caller %p)\n", name, __builtin_return_address(0));
            fflush(stderr);
        }
        errno = LE_INVAL; return -1; }
    }
}

static int64_t SYSV _sh_getauxval(uint64_t type)
{
    switch (type) { case 6: return 4096; case 17: return 100; default: errno = LE_NOENT; return 0; }
}

static int SYSV _sh_prctl(int opt, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5)
{
    (void)a3; (void)a4; (void)a5;
    if (opt == 15 /* PR_SET_NAME */ || opt == 38 /* PR_SET_NO_NEW_PRIVS */) return 0;
    if (opt == 16 /* PR_GET_NAME */) { if (a2) { memcpy((void *)(uintptr_t)a2, "adam\0\0\0\0\0\0\0\0\0\0\0\0", 16); } return 0; }
    fprintf(stderr, "[guest-libc] prctl(%d): option not supported on Windows, failing with EINVAL (guest caller %p)\n", opt, __builtin_return_address(0));
    fflush(stderr);
    errno = LE_INVAL; return -1;
}

static int SYSV _sh_sysinfo(void *out)
{
    struct { int64_t uptime; uint64_t loads[3]; uint64_t totalram, freeram, sharedram, bufferram, totalswap, freeswap;
             uint16_t procs, pad; uint32_t pad2; uint64_t totalhigh, freehigh; uint32_t mem_unit; char f[4]; } *si = out;
    MEMORYSTATUSEX ms;
    if (!si) { errno = LE_INVAL; return -1; }
    memset(si, 0, sizeof *si);
    ms.dwLength = sizeof ms; GlobalMemoryStatusEx(&ms);
    si->uptime = (int64_t)(GetTickCount64() / 1000);
    si->totalram = ms.ullTotalPhys; si->freeram = ms.ullAvailPhys;
    si->totalswap = ms.ullTotalPageFile > ms.ullTotalPhys ? ms.ullTotalPageFile - ms.ullTotalPhys : 0;
    si->freeswap = ms.ullAvailPageFile > ms.ullAvailPhys ? ms.ullAvailPageFile - ms.ullAvailPhys : 0;
    si->procs = 1; si->mem_unit = 1;
    return 0;
}

static int SYSV _sh_gethostname(char *name, size_t len)
{
    DWORD n = (DWORD)len;
    if (!name || !len) { errno = LE_INVAL; return -1; }
    if (!GetComputerNameA(name, &n)) { snprintf(name, len, "adam"); }
    name[len - 1] = 0; return 0;
}

static int SYSV _sh_gettimeofday(int64_t *tv, void *tz)
{
    FILETIME ft; uint64_t t; (void)tz;
    if (!tv) return 0;
    GetSystemTimePreciseAsFileTime(&ft);
    t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    t -= 116444736000000000ULL;
    tv[0] = (int64_t)(t / 10000000ULL); tv[1] = (int64_t)((t % 10000000ULL) / 10ULL);
    return 0;
}
static unsigned SYSV _sh_sleep(unsigned s)      { Sleep(s * 1000u); return 0; }
static int      SYSV _sh_usleep(unsigned us)    { Sleep(us ? (us + 999) / 1000 : 0); return 0; }
static void SYSV _sh_arc4random_buf(void *b, size_t n) { if (b && n) SystemFunction036(b, (unsigned long)n); }
static uint32_t SYSV _sh_arc4random(void)       { uint32_t v = 0; SystemFunction036(&v, sizeof v); return v; }
static int SYSV _sh_isatty(int fd)              { (void)fd; errno = LE_NOTTY; return 0; }

/* ── signals: handlers are accepted and never delivered ───────────────────── */
static int SYSV _sh_sigaction(int sig, const void *act, void *old)
{
    (void)sig;
    if (act) SH_ONCE("sigaction", "signal handlers are accepted but never delivered on Windows");
    if (old) memset(old, 0, 32);                 /* bionic LP64 struct sigaction */
    return 0;
}
static int SYSV _sh_sigprocmask(int how, const void *set, void *old) { (void)how; (void)set; if (old) *(uint64_t *)old = 0; return 0; }
static int SYSV _sh_sigaltstack(const void *ss, void *old)
{ (void)ss; if (old) { memset(old, 0, 24); *(int *)((char *)old + 8) = 2 /* SS_DISABLE */; } return 0; }
static int SYSV _sh_setitimer(int which, const void *nv, void *ov)
{ (void)which; (void)nv; SH_ONCE("setitimer", "interval timers/SIGALRM are not delivered on Windows"); if (ov) memset(ov, 0, 32); return 0; }
static int SYSV _sh_kill(int pid, int sig)
{
    if (sig == 0) { if (pid == (int)GetCurrentProcessId()) return 0; errno = LE_SRCH; return -1; }
    if (pid == (int)GetCurrentProcessId() && sig == 6) { fprintf(stderr, "[guest-libc] guest raised SIGABRT (kill)\n"); fflush(stderr); abort(); }
    fprintf(stderr, "[guest-libc] kill(%d, %d): signals are not supported on Windows, failing with EPERM (guest caller %p)\n", pid, sig, __builtin_return_address(0));
    fflush(stderr); errno = LE_PERM; return -1;
}
static int SYSV _sh_tgkill(int tgid, int tid, int sig)
{
    (void)tgid; (void)tid;
    if (sig == 0) return 0;
    if (sig == 6) { fprintf(stderr, "[guest-libc] guest raised SIGABRT (tgkill)\n"); fflush(stderr); abort(); }
    fprintf(stderr, "[guest-libc] tgkill(sig %d): signals are not supported on Windows, failing with EPERM (guest caller %p)\n", sig, __builtin_return_address(0));
    fflush(stderr); errno = LE_PERM; return -1;
}

/* ── memory advice / locking: harmless to ignore ──────────────────────────── */
static int SYSV _sh_zero_ok(void) { return 0; }
static void *SYSV _sh_mremap(void *a, size_t o, size_t n, int fl)
{ (void)a; (void)o; (void)n; (void)fl; SH_ONCE("mremap", "not supported on Windows, failing with ENOMEM"); errno = LE_NOMEM; return (void *)(intptr_t)-1; }
static void *SYSV _sh_sbrk(intptr_t inc)
{ (void)inc; SH_ONCE("sbrk", "not supported on Windows, failing with ENOMEM"); errno = LE_NOMEM; return (void *)(intptr_t)-1; }

/* ── file descriptors ─────────────────────────────────────────────────────── */
static int SYSV _sh_dup(int fd)
{ if (_net_is_fd(fd) || _dirfd_is(fd)) { errno = LE_BADF; return -1; } return _dup(fd); }
static int SYSV _sh_dup2(int a, int b)
{ if (_net_is_fd(a) || _dirfd_is(a)) { errno = LE_BADF; return -1; } return _dup2(a, b) == 0 ? b : -1; }
static int SYSV _sh_dup3(int a, int b, int fl)
{ (void)fl; if (a == b) { errno = LE_INVAL; return -1; } return _sh_dup2(a, b); }
static int SYSV _sh_pipe2(int *fds, int fl)
{
    if (!fds) { errno = LE_INVAL; return -1; }
    if (fl & 04000) SH_ONCE("pipe2", "O_NONBLOCK is not supported on Windows pipes; creating a blocking pipe");
    return _pipe(fds, 65536, _O_BINARY);
}
static int64_t SYSV _sh_writev(int fd, const void *iov, int cnt)
{
    const struct { void *base; size_t len; } *v = iov; int64_t total = 0;
    if (cnt < 0 || (cnt && !v)) { errno = LE_INVAL; return -1; }
    for (int i = 0; i < cnt; i++) {
        int64_t w = _sysv_write(fd, v[i].base, v[i].len);
        if (w < 0) return total ? total : -1;
        total += w;
        if ((size_t)w < v[i].len) break;
    }
    return total;
}
static int SYSV _sh_epoll_pwait(int ep, void *ev, int max, int timeout, const void *sigmask)
{ (void)sigmask; return _net_epoll_wait(ep, ev, max, timeout); }

/* ── paths relative to a directory descriptor ─────────────────────────────── */
/* Only AT_FDCWD or an absolute path can be honoured: a real directory fd has no
 * Windows counterpart in this layer. */
static int _sh_atok(const char *name, int dirfd, const char *path)
{
    if (_lowp(path)) { errno = LE_INVAL; return 0; }
    if (dirfd == SH_AT_FDCWD || path[0] == '/' || path[0] == '\\') return 1;
    fprintf(stderr, "[guest-libc] %s: relative path \"%s\" against directory fd %d is not supported on Windows, failing with EBADF\n", name, path, dirfd);
    fflush(stderr); errno = LE_BADF; return 0;
}
static int SYSV _sh_faccessat(int d, const char *p, int mode, int fl) { (void)fl; return _sh_atok("faccessat", d, p) ? _sysv_access(p, mode) : -1; }
static int SYSV _sh_fstatat(int d, const char *p, void *st, int fl)
{ if (!_sh_atok("fstatat", d, p)) return -1; return (fl & SH_AT_SYMLINK_NOFOLLOW) ? _sysv_lstat(p, st) : _sysv_stat(p, st); }
static int SYSV _sh_mkdirat(int d, const char *p, int mode) { return _sh_atok("mkdirat", d, p) ? _sysv_mkdir(p, mode) : -1; }
static int SYSV _sh_unlinkat(int d, const char *p, int fl)
{
    if (!_sh_atok("unlinkat", d, p)) return -1;
    return (fl & SH_AT_REMOVEDIR) ? _rmdir(_winpath(p)) : _sysv_unlink(p);
}
static int SYSV _sh_renameat(int od, const char *o, int nd, const char *n)
{
    if (!_sh_atok("renameat", od, o) || !_sh_atok("renameat", nd, n)) return -1;
    /* POSIX rename replaces an existing destination; MoveFileEx does the same. */
    if (!MoveFileExA(_winpath(o), _winpath(n), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
        DWORD e = GetLastError();
        errno = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ? LE_NOENT : (e == ERROR_ACCESS_DENIED || e == ERROR_SHARING_VIOLATION) ? 13 : LE_INVAL;
        return -1;
    }
    return 0;
}
static int64_t SYSV _sh_readlinkat(int d, const char *p, char *buf, size_t sz) { return _sh_atok("readlinkat", d, p) ? _sysv_readlink(p, buf, sz) : -1; }
static int SYSV _sh_fchmodat(int d, const char *p, int mode, int fl)
{ (void)mode; (void)fl; if (!_sh_atok("fchmodat", d, p)) return -1; if (_access(_winpath(p), 0)) { errno = LE_NOENT; return -1; } return 0; }
static int SYSV _sh_fchownat(int d, const char *p, int u, int g, int fl)
{ (void)u; (void)g; (void)fl; if (!_sh_atok("fchownat", d, p)) return -1; if (_access(_winpath(p), 0)) { errno = LE_NOENT; return -1; } return 0; }
static int SYSV _sh_utimensat(int d, const char *p, const int64_t *ts, int fl)
{
    struct __utimbuf64 ub; time_t now = time(NULL); (void)fl;
    if (!_sh_atok("utimensat", d, p)) return -1;
    ub.actime  = (ts && ts[1] != 0x3ffffffe) ? (ts[1] == 0x3fffffff ? now : (time_t)ts[0]) : now;
    ub.modtime = (ts && ts[3] != 0x3ffffffe) ? (ts[3] == 0x3fffffff ? now : (time_t)ts[2]) : now;
    if (_utime64(_winpath(p), &ub)) { if (errno == ENOENT) errno = LE_NOENT; return -1; }
    return 0;
}
static int SYSV _sh_chdir(const char *p)
{ if (_lowp(p)) { errno = LE_INVAL; return -1; } if (_chdir(_winpath(p))) { errno = LE_NOENT; return -1; } return 0; }
static int SYSV _sh_truncate(const char *p, int64_t len)
{
    HANDLE h; LARGE_INTEGER li; int ok;
    if (_lowp(p) || len < 0) { errno = LE_INVAL; return -1; }
    h = CreateFileA(_winpath(p), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { errno = LE_NOENT; return -1; }
    li.QuadPart = len;
    ok = SetFilePointerEx(h, li, NULL, FILE_BEGIN) && SetEndOfFile(h);
    CloseHandle(h);
    if (!ok) { errno = LE_INVAL; return -1; }
    return 0;
}
static void _sh_fill_statfs(void *out, const char *path)
{
    struct { int64_t type, bsize; uint64_t blocks, bfree, bavail, files, ffree; int fsid[2]; int64_t namelen, frsize, flags, spare[4]; } *s = out;
    ULARGE_INTEGER avail, total, freeb;
    memset(s, 0, sizeof *s);
    if (!GetDiskFreeSpaceExA(path, &avail, &total, &freeb)) { total.QuadPart = avail.QuadPart = freeb.QuadPart = 0; }
    s->type = 0xEF53; s->bsize = 4096; s->frsize = 4096; s->namelen = 255;
    s->blocks = total.QuadPart / 4096; s->bfree = freeb.QuadPart / 4096; s->bavail = avail.QuadPart / 4096;
}
static int SYSV _sh_statfs(const char *p, void *out)
{ if (_lowp(p) || !out) { errno = LE_INVAL; return -1; } _sh_fill_statfs(out, _winpath(p)); return 0; }
static int SYSV _sh_fstatfs(int fd, void *out)
{ (void)fd; if (!out) { errno = LE_INVAL; return -1; } _sh_fill_statfs(out, NULL); return 0; }
/* flock: this process is the only user of the files it locks, so an advisory
 * whole-file lock can always be granted. */
static int SYSV _sh_flock(int fd, int op) { (void)fd; (void)op; SH_ONCE("flock", "advisory locks are granted without locking (single-process)"); return 0; }
static int SYSV _sh_fallocate(int fd, int mode, int64_t off, int64_t len)
{
    int64_t want, have;
    if (_net_is_fd(fd) || _dirfd_is(fd)) { errno = LE_BADF; return -1; }
    if (mode & ~1) { errno = LE_OPNOTSUPP; return -1; }          /* only plain / KEEP_SIZE */
    if (mode & 1) return 0;                                      /* KEEP_SIZE: no visible effect */
    want = off + len; have = _filelengthi64(fd);
    if (have < 0) { errno = LE_BADF; return -1; }
    if (want > have && _chsize_s(fd, want)) { errno = LE_NOMEM; return -1; }
    return 0;
}
/* Directory enumeration: DIR* handles are synthetic here, so getdents is not
 * available.  Report an empty directory, once, rather than crash. */
static void *SYSV _sh_readdir(void *dirp)
{ (void)dirp; SH_ONCE("readdir", "directory enumeration is not supported on Windows; directories read as empty"); return NULL; }
static int SYSV _sh_readdir_r(void *dirp, void *entry, void **result)
{ (void)dirp; (void)entry; SH_ONCE("readdir_r", "directory enumeration is not supported on Windows; directories read as empty"); if (result) *result = NULL; return 0; }

/* ── name resolution: getaddrinfo is the supported path ───────────────────── */
static int SYSV _sh_android_getaddrinfofornet(const char *host, const char *serv, const void *hints, unsigned netid, unsigned mark, void **res)
{ (void)netid; (void)mark; return _net_getaddrinfo(host, serv, hints, res); }
static void *SYSV _sh_null_resolver(void)
{ SH_ONCE("gethostby*/getservby*", "legacy resolver calls are not supported; use getaddrinfo (returning NULL)"); return NULL; }
static int SYSV _sh_getnameinfo(const void *sa, unsigned sl, char *h, unsigned hl, char *s, unsigned sv, int fl)
{ (void)sa; (void)sl; (void)h; (void)hl; (void)s; (void)sv; (void)fl; SH_ONCE("getnameinfo", "reverse lookup is not supported on Windows, failing with EAI_FAIL"); return 4; }
static char *SYSV _sh_if_indextoname(unsigned idx, char *name)
{ (void)idx; (void)name; SH_ONCE("if_indextoname", "interface names are not available on Windows, failing with ENXIO"); errno = LE_NXIO; return NULL; }

/* ── Android system properties: nothing is ever set ───────────────────────── */
static int  SYSV _sh_sysprop_get(const char *name, char *value) { (void)name; if (value) value[0] = 0; return 0; }
static const void *SYSV _sh_sysprop_find(const char *name)      { (void)name; return NULL; }
static int  SYSV _sh_sysprop_read(const void *pi, char *name, char *value) { (void)pi; if (name) name[0] = 0; if (value) value[0] = 0; return 0; }
static unsigned SYSV _sh_sysprop_serial(const void *pi)         { (void)pi; return 0; }
static int  SYSV _sh_sysprop_foreach(void *cb, void *cookie)    { (void)cb; (void)cookie; return 0; }

/* ── stdio on host FILE objects ───────────────────────────────────────────────
 * fopen/fclose/fread/fwrite are already hooked to the host CRT, so every FILE*
 * the guest holds is a host FILE*.  Bionic's own fgets/fputs/... would
 * interpret those with the wrong struct layout, so the rest of the family must
 * use the host CRT as well.  The guest's stdin/stdout/stderr are slots of
 * bionic's __sF array (3 x 152 bytes); map them to the host streams. */
static FILE *_sh_hf(void *f)
{
    static uintptr_t sf;
    uintptr_t p = (uintptr_t)f;
    if (!sf) {
        void *h = android_dlopen("libc.so", 2 /*RTLD_NOW*/);
        void *s = h ? android_dlsym(h, "__sF") : NULL;
        sf = s ? (uintptr_t)s : 1;
    }
    if (p >= sf && p < sf + 3 * 152) {
        switch ((p - sf) / 152) { case 0: return stdin; case 1: return stdout; default: return stderr; }
    }
    return (FILE *)f;
}
static void *SYSV _sh_fdopen(int fd, const char *m)  { return _lowp(m) ? NULL : (void *)_fdopen(fd, m); }
static char *SYSV _sh_fgets(char *b, int n, void *f) { return (_lowp(b) || !f) ? NULL : fgets(b, n, _sh_hf(f)); }
static int   SYSV _sh_fputs(const char *s, void *f)  { return (_lowp(s) || !f) ? -1 : fputs(s, _sh_hf(f)); }
static int   SYSV _sh_fputc(int c, void *f)          { return f ? fputc(c, _sh_hf(f)) : -1; }
static int   SYSV _sh_getc(void *f)                  { return f ? fgetc(_sh_hf(f)) : -1; }
static int   SYSV _sh_getchar(void)                  { return getchar(); }
static int   SYSV _sh_puts(const char *s)            { return _lowp(s) ? -1 : puts(s); }
static int   SYSV _sh_fflush(void *f)                { return f ? fflush(_sh_hf(f)) : fflush(NULL); }
static int   SYSV _sh_fseek(void *f, int64_t o, int w)  { return f ? _fseeki64(_sh_hf(f), o, w) : -1; }
static int64_t SYSV _sh_ftell(void *f)               { return f ? _ftelli64(_sh_hf(f)) : -1; }
static void  SYSV _sh_rewind(void *f)                { if (f) rewind(_sh_hf(f)); }
static int   SYSV _sh_feof(void *f)                  { return f ? feof(_sh_hf(f)) : 0; }
static int   SYSV _sh_ferror(void *f)                { return f ? ferror(_sh_hf(f)) : 0; }
static void  SYSV _sh_clearerr(void *f)              { if (f) clearerr(_sh_hf(f)); }
static int   SYSV _sh_fileno(void *f)                { return f ? _fileno(_sh_hf(f)) : -1; }
static int   SYSV _sh_ungetc(int c, void *f)         { return f ? ungetc(c, _sh_hf(f)) : -1; }
static void  SYSV _sh_setbuf(void *f, char *b)       { (void)f; (void)b; }
static int   SYSV _sh_setvbuf(void *f, char *b, int m, size_t s) { (void)f; (void)b; (void)m; (void)s; return 0; }
static void  SYSV _sh_flockfile(void *f)             { (void)f; }

/* ── the table consulted by hybris_get_hooked_symbol ──────────────────────── */
static const struct _w32_hook win32_shim_hooks[] = {
    /* formatted output */
    HA(snprintf,_sh_snprintf), HA(vsnprintf,_sh_vsnprintf), HA(sprintf,_sh_sprintf), HA(vsprintf,_sh_vsprintf),
    HA(syslog,_sh_syslog), HA(vsyslog,_sh_vsyslog), HA(openlog,_sh_openlog), HA(closelog,_sh_closelog),
    /* fatal paths */
    HA(__stack_chk_fail,_sh_stack_chk_fail), HA(__assert2,_sh___assert2), HA(__assert,_sh___assert),
    HA(android_set_abort_message,_sh_android_set_abort_message), HA(_Exit,_sh__Exit),
    /* identity, limits, system info */
    HA(getpid,_sh_getpid), HA(gettid,_sh_gettid), HA(getuid,_sh_getuid), HA(geteuid,_sh_getuid),
    HA(getgid,_sh_getuid), HA(getegid,_sh_getuid), HA(getpgid,_sh_getpgid),
    HA(getpriority,_sh_getpriority), HA(setpriority,_sh_setpriority),
    HA(sched_getscheduler,_sh_sched_ok), HA(sched_setscheduler,_sh_sched_ok), HA(sched_getparam,_sh_sched_getparam),
    HA(umask,_sh_umask), HA(getpagesize,_sh_getpagesize),
    HA(pthread_setname_np,_sh_pthread_setname_np), HA(pthread_gettid_np,_sh_pthread_gettid_np),
    HA(pthread_attr_getstack,_sh_pthread_attr_getstack),
    HA(getrlimit,_sh_getrlimit), HA(sysconf,_sh_sysconf), HA(getauxval,_sh_getauxval), HA(prctl,_sh_prctl),
    HA(sysinfo,_sh_sysinfo), HA(gethostname,_sh_gethostname), HA(gettimeofday,_sh_gettimeofday),
    HA(sleep,_sh_sleep), HA(usleep,_sh_usleep), HA(arc4random,_sh_arc4random), HA(arc4random_buf,_sh_arc4random_buf),
    HA(isatty,_sh_isatty),
    HA(setpgid,_shu_setpgid), HA(setsid,_shu_setsid), HA(setgroups,_shu_setgroups),
    HA(setresuid,_shu_setresuid), HA(setresgid,_shu_setresgid),
    /* signals and processes */
    HA(sigaction,_sh_sigaction), HA(sigprocmask,_sh_sigprocmask), HA(sigaltstack,_sh_sigaltstack),
    HA(setitimer,_sh_setitimer), HA(kill,_sh_kill), HA(tgkill,_sh_tgkill),
    HA(sigsuspend,_shu_sigsuspend), HA(signalfd,_shu_signalfd),
    HA(fork,_shu_fork), HA(vfork,_shu_vfork), HA(clone,_shu_clone), HA(execve,_shu_execve),
    HA(wait4,_shu_wait4), HA(umount2,_shu_umount2),
    /* memory */
    HA(madvise,_sh_zero_ok), HA(mlock,_sh_zero_ok), HA(mremap,_sh_mremap), HA(sbrk,_sh_sbrk),
    /* descriptors and I/O */
    HA(dup,_sh_dup), HA(dup2,_sh_dup2), HA(dup3,_sh_dup3), HA(pipe2,_sh_pipe2), HA(writev,_sh_writev),
    HA(pread,_sysv_pread64), HA(pwrite,_sysv_pwrite64),
    HA(epoll_pwait,_sh_epoll_pwait), HA(pselect,_shu_pselect), HA(inotify_init1,_shu_inotify_init1),
    /* paths */
    HA(faccessat,_sh_faccessat), HA(fstatat,_sh_fstatat), HA(mkdirat,_sh_mkdirat), HA(unlinkat,_sh_unlinkat),
    HA(renameat,_sh_renameat), HA(readlinkat,_sh_readlinkat), HA(fchmodat,_sh_fchmodat), HA(fchownat,_sh_fchownat),
    HA(utimensat,_sh_utimensat), HA(chdir,_sh_chdir), HA(truncate,_sh_truncate),
    HA(statfs,_sh_statfs), HA(fstatfs,_sh_fstatfs), HA(flock,_sh_flock),
    HA(fallocate,_sh_fallocate), HA(fallocate64,_sh_fallocate),
    HA(posix_fadvise,_sh_zero_ok), HA(posix_fadvise64,_sh_zero_ok),
    HA(readdir,_sh_readdir), HA(readdir_r,_sh_readdir_r),
    HA(linkat,_shu_linkat), HA(symlinkat,_shu_symlinkat), HA(mknodat,_shu_mknodat), HA(fchdir,_shu_fchdir),
    /* name resolution */
    HA(android_getaddrinfofornet,_sh_android_getaddrinfofornet),
    HA(gethostbyname,_sh_null_resolver), HA(getservbyname,_sh_null_resolver),
    HA(android_gethostbynamefornet,_sh_null_resolver), HA(android_gethostbyaddrfornet,_sh_null_resolver),
    HA(getnameinfo,_sh_getnameinfo), HA(if_indextoname,_sh_if_indextoname),
    HA(__res_nameinquery,_shu___res_nameinquery), HA(__res_nsend,_shu___res_nsend),
    HA(__res_queriesmatch,_shu___res_queriesmatch),
    /* Android system properties */
    HA(__system_property_get,_sh_sysprop_get), HA(__system_property_find,_sh_sysprop_find),
    HA(__system_property_read,_sh_sysprop_read), HA(__system_property_serial,_sh_sysprop_serial),
    HA(__system_property_foreach,_sh_sysprop_foreach), HA(__system_properties_init,_sh_zero_ok),
    /* stdio on host FILE objects */
    HA(fdopen,_sh_fdopen), HA(fgets,_sh_fgets), HA(fputs,_sh_fputs), HA(fputc,_sh_fputc), HA(putc,_sh_fputc),
    HA(putc_unlocked,_sh_fputc), HA(getc,_sh_getc), HA(getc_unlocked,_sh_getc), HA(getchar_unlocked,_sh_getchar),
    HA(puts,_sh_puts), HA(fflush,_sh_fflush), HA(fseek,_sh_fseek), HA(fseeko,_sh_fseek), HA(ftell,_sh_ftell),
    HA(ftello,_sh_ftell), HA(rewind,_sh_rewind), HA(feof,_sh_feof), HA(ferror,_sh_ferror), HA(clearerr,_sh_clearerr),
    HA(fileno,_sh_fileno), HA(ungetc,_sh_ungetc), HA(setbuf,_sh_setbuf), HA(setvbuf,_sh_setvbuf),
    HA(flockfile,_sh_flockfile), HA(funlockfile,_sh_flockfile),
    { NULL, NULL }
};

#endif /* HYBRIS_WINDOWS_LIBC_SHIMS_H */
