#ifndef HYBRIS_WINDOWS_CORE_COMPAT_H
#define HYBRIS_WINDOWS_CORE_COMPAT_H

/* Keep the public wrapper build honest on Windows.  This header supplies only
 * the small libc seams that have no UCRT equivalent; unsupported Linux
 * facilities return ENOSYS rather than pretending to work. */
#if defined(_WIN32)

#include <windows.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <io.h>
#include <process.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>

#ifndef RTLD_NOW
#define RTLD_NOW 2
#define RTLD_LOCAL 0
#define RTLD_GLOBAL 0x100
#endif
static __declspec(thread) char hybris_windows_dlerror[128];
static inline void *dlopen(const char *path, int flags) {
    (void)flags;
    HMODULE module = LoadLibraryA(path);
    if (!module) snprintf(hybris_windows_dlerror, sizeof(hybris_windows_dlerror),
                          "LoadLibraryA failed (%lu)", (unsigned long)GetLastError());
    return (void *)module;
}
static inline void *dlsym(void *handle, const char *name) {
    FARPROC symbol = GetProcAddress((HMODULE)handle, name);
    if (!symbol) snprintf(hybris_windows_dlerror, sizeof(hybris_windows_dlerror),
                          "GetProcAddress failed (%lu)", (unsigned long)GetLastError());
    return (void *)symbol;
}
static inline char *dlerror(void) {
    return hybris_windows_dlerror[0] ? hybris_windows_dlerror : NULL;
}
static inline int dlclose(void *handle) {
    if (FreeLibrary((HMODULE)handle)) return 0;
    errno = ENOSYS;
    return -1;
}

typedef int64_t off64_t;
typedef fpos_t fpos64_t;
#ifndef CLOCK_REALTIME
typedef int clockid_t;
#define CLOCK_REALTIME 0
#endif
static inline int hybris_windows_clock_gettime(clockid_t clock_id, struct timespec *ts) {
    FILETIME now;
    ULARGE_INTEGER ticks;
    if (clock_id != CLOCK_REALTIME || ts == NULL) {
        errno = EINVAL;
        return -1;
    }
    GetSystemTimeAsFileTime(&now);
    ticks.LowPart = now.dwLowDateTime;
    ticks.HighPart = now.dwHighDateTime;
    /* FILETIME is expressed in 100 ns intervals since 1601-01-01. */
    ticks.QuadPart -= UINT64_C(116444736000000000);
    ts->tv_sec = (time_t)(ticks.QuadPart / UINT64_C(10000000));
    ts->tv_nsec = (long)((ticks.QuadPart % UINT64_C(10000000)) * 100);
    return 0;
}
#define clock_gettime hybris_windows_clock_gettime

#ifndef __NR_gettid
#define __NR_gettid 0
#endif
#ifndef __kernel_off_t
typedef int64_t __kernel_off_t;
#endif

#define fgetpos64 fgetpos
#define fsetpos64 fsetpos
#define fseeko _fseeki64
#define fseeko64 _fseeki64
#define ftello64 _ftelli64
#define fileno _fileno
#define unlink _unlink
#define close _close
#define read _read
#define write _write
#define getpid _getpid
#define strcasecmp _stricmp
#define strncasecmp _strnicmp

static inline int hybris_windows_unsupported(void) { errno = ENOSYS; return -1; }
static inline long hybris_windows_getauxval(unsigned long type) {
    (void)type; errno = ENOSYS; return 0;
}
static inline int hybris_windows_prctl(int option, unsigned long a2,
                                       unsigned long a3, unsigned long a4,
                                       unsigned long a5) {
    (void)option; (void)a2; (void)a3; (void)a4; (void)a5;
    return hybris_windows_unsupported();
}
static inline int hybris_windows_pthread_setname_np(pthread_t thread,
                                                     const char *name) {
    (void)thread; (void)name; return hybris_windows_unsupported();
}
static inline int hybris_windows_fork(void) { return hybris_windows_unsupported(); }
static inline int hybris_windows_pthread_cond_clockwait(pthread_cond_t *cond,
                                                         pthread_mutex_t *mutex,
                                                         clockid_t clock_id,
                                                         const struct timespec *when) {
    if (clock_id != CLOCK_REALTIME) return hybris_windows_unsupported();
    return pthread_cond_timedwait(cond, mutex, when);
}
static inline int hybris_windows_pthread_atfork(void (*prepare)(void),
                                                 void (*parent)(void),
                                                 void (*child)(void)) {
    (void)prepare; (void)parent; (void)child; return hybris_windows_unsupported();
}
static inline size_t hybris_windows_malloc_usable_size(void *ptr) {
    (void)ptr; errno = ENOSYS; return 0;
}
static inline int hybris_windows_pthread_getattr_np(pthread_t thread,
                                                     pthread_attr_t *attr) {
    (void)thread; (void)attr; return hybris_windows_unsupported();
}
static inline int hybris_windows_rwlock_kind(pthread_rwlockattr_t *attr, int kind) {
    (void)attr; (void)kind; return hybris_windows_unsupported();
}

/* Linux extended attributes are not a property of the Windows filesystem. */
static inline ssize_t getxattr(const char *p, const char *n, void *v, size_t s) {
    (void)p; (void)n; (void)v; (void)s; return (ssize_t)hybris_windows_unsupported();
}
static inline ssize_t setxattr(const char *p, const char *n, const void *v,
                               size_t s, int f) {
    (void)p; (void)n; (void)v; (void)s; (void)f;
    return (ssize_t)hybris_windows_unsupported();
}

struct mntent { char *mnt_fsname, *mnt_dir, *mnt_type, *mnt_opts; int mnt_freq, mnt_passno; };
static inline FILE *setmntent(const char *path, const char *type) {
    (void)path; (void)type; errno = ENOSYS; return NULL;
}
static inline struct mntent *getmntent(FILE *stream) {
    (void)stream; errno = ENOSYS; return NULL;
}
static inline struct mntent *getmntent_r(FILE *stream, struct mntent *entry,
                                         char *buf, int buflen) {
    (void)stream; (void)entry; (void)buf; (void)buflen; errno = ENOSYS; return NULL;
}
static inline int endmntent(FILE *stream) {
    (void)stream; return hybris_windows_unsupported();
}

/* No syslog service is assumed for a native Windows host. */
static inline void openlog(const char *id, int option, int facility) {
    (void)id; (void)option; (void)facility;
}
static inline void closelog(void) {}
static inline void syslog(int priority, const char *format, ...) {
    (void)priority; (void)format;
}
static inline void vsyslog(int priority, const char *format, va_list ap) {
    (void)priority; (void)format; (void)ap;
}

#define getauxval hybris_windows_getauxval
#define prctl hybris_windows_prctl
#define pthread_setname_np hybris_windows_pthread_setname_np
#define fork hybris_windows_fork
#define pthread_cond_clockwait hybris_windows_pthread_cond_clockwait
#ifndef pthread_atfork
#define pthread_atfork hybris_windows_pthread_atfork
#endif
#define malloc_usable_size hybris_windows_malloc_usable_size
#define pthread_getattr_np hybris_windows_pthread_getattr_np
#define pthread_rwlockattr_setkind_np hybris_windows_rwlock_kind
#define pthread_rwlockattr_getkind_np(a, k) (hybris_windows_unsupported())

#endif
#endif
