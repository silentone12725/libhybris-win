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
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <locale.h>
#include <malloc.h>
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
#define access _access
#define getpid _getpid
#define strcasecmp _stricmp
#define strncasecmp _strnicmp

static inline int hybris_windows_setenv(const char *name, const char *value, int overwrite) {
    if (!overwrite && getenv(name) != NULL) return 0;
    return _putenv_s(name, value != NULL ? value : "");
}
#define setenv hybris_windows_setenv

/*
 * hooks.c releases allocator results with ordinary free(). MinGW's dedicated
 * aligned allocators instead require __mingw_aligned_free(), so using them
 * here would create an ownership bug. This shim therefore supports the
 * alignment guaranteed by malloc and reports larger alignments as ENOSYS. The
 * returned pointer is consequently always directly free()-owned.
 */
static inline int hybris_windows_posix_memalign(void **memptr,
                                                size_t alignment,
                                                size_t size) {
    void *result;

    if (memptr == NULL || alignment < sizeof(void *) ||
        (alignment & (alignment - 1)) != 0 ||
        (alignment % sizeof(void *)) != 0) {
        return EINVAL;
    }
    if (alignment > __alignof__(max_align_t)) {
        errno = ENOSYS;
        return ENOSYS;
    }

    result = malloc(size);
    if (result == NULL)
        return ENOMEM;

    *memptr = result;
    return 0;
}

#if defined(__MINGW32__)
static inline void *hybris_windows_aligned_alloc(size_t alignment, size_t size) {
    if (alignment < sizeof(void *) ||
        (alignment & (alignment - 1)) != 0 ||
        (alignment % sizeof(void *)) != 0 ||
        (size % alignment) != 0) {
        errno = EINVAL;
        return NULL;
    }
    if (alignment > __alignof__(max_align_t)) {
        errno = ENOSYS;
        return NULL;
    }
    return malloc(size);
}
#endif

/* A Windows console is a terminal, but it is not a POSIX pseudo-terminal. */
static __declspec(thread) char hybris_windows_tty_name[16];
static inline const char *hybris_windows_console_name(int fd) {
    intptr_t raw_handle;
    HANDLE handle;
    DWORD mode;
    CONSOLE_SCREEN_BUFFER_INFO info;

    raw_handle = _get_osfhandle(fd);
    if (raw_handle == (intptr_t)-1) {
        errno = EBADF;
        return NULL;
    }
    handle = (HANDLE)raw_handle;
    if (!GetConsoleMode(handle, &mode)) {
        errno = ENOTTY;
        return NULL;
    }

    if (GetConsoleScreenBufferInfo(handle, &info))
        strcpy(hybris_windows_tty_name, "CONOUT$");
    else
        strcpy(hybris_windows_tty_name, "CONIN$");
    return hybris_windows_tty_name;
}
static inline char *hybris_windows_ttyname(int fd) {
    return (char *)hybris_windows_console_name(fd);
}
static inline char *hybris_windows_ptsname(int fd) {
    /* Windows consoles have no separate slave device; expose the console
     * endpoint itself, which is useful to callers that only need a stable
     * terminal name. Non-console handles remain an explicit ENOTTY failure. */
    return (char *)hybris_windows_console_name(fd);
}

/* Also prevents the older Q-only Windows mman shim from being reintroduced
 * when a core translation unit includes <sys/mman.h> after this header. */
#ifndef HYBRIS_WINDOWS_SYS_MMAN_H
#define HYBRIS_WINDOWS_SYS_MMAN_H

#ifndef PROT_NONE
#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x02
#endif
#ifndef MAP_SHARED
#define MAP_SHARED 0x01
#endif
#ifndef MAP_FIXED
#define MAP_FIXED 0x10
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif
#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0x4000
#endif
#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

static inline DWORD hybris_windows_mmap_protection(int prot) {
    switch (prot) {
    case PROT_NONE:
        return PAGE_NOACCESS;
    case PROT_READ:
        return PAGE_READONLY;
    case PROT_READ | PROT_WRITE:
        return PAGE_READWRITE;
    case PROT_EXEC:
        return PAGE_EXECUTE;
    case PROT_READ | PROT_EXEC:
        return PAGE_EXECUTE_READ;
    case PROT_READ | PROT_WRITE | PROT_EXEC:
        return PAGE_EXECUTE_READWRITE;
    default:
        return 0;
    }
}

/*
 * The core wrapper only needs private anonymous mappings. Windows has no safe
 * drop-in for POSIX MAP_FIXED or arbitrary file-backed mappings without
 * retaining view-offset metadata, so those requests fail explicitly.
 */
static inline void *hybris_windows_mmap(void *address, size_t length, int prot,
                                        int flags, int fd, off64_t offset) {
    const int supported_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
    DWORD protection;
    void *result;

    (void)fd;
    (void)offset;
    if (length == 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    if ((flags & MAP_ANONYMOUS) == 0 || (flags & MAP_PRIVATE) == 0 ||
        (flags & ~supported_flags) != 0) {
        errno = ENOSYS;
        return MAP_FAILED;
    }
    protection = hybris_windows_mmap_protection(prot);
    if (protection == 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }

    result = VirtualAlloc(address, length, MEM_RESERVE | MEM_COMMIT, protection);
    /* POSIX treats a non-fixed address as a hint; retry without the hint. */
    if (result == NULL && address != NULL)
        result = VirtualAlloc(NULL, length, MEM_RESERVE | MEM_COMMIT, protection);
    if (result == NULL) {
        errno = ENOMEM;
        return MAP_FAILED;
    }
    return result;
}

static inline void *hybris_windows_mmap64(void *address, size_t length, int prot,
                                          int flags, int fd, off64_t offset) {
    return hybris_windows_mmap(address, length, prot, flags, fd, offset);
}

static inline int hybris_windows_munmap(void *address, size_t length) {
    if (address == NULL || address == MAP_FAILED || length == 0) {
        errno = EINVAL;
        return -1;
    }
    if (!VirtualFree(address, 0, MEM_RELEASE)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static inline int hybris_windows_mprotect(void *address, size_t length, int prot) {
    DWORD old_protection;
    DWORD protection;

    if (address == NULL || address == MAP_FAILED || length == 0) {
        errno = EINVAL;
        return -1;
    }
    protection = hybris_windows_mmap_protection(prot);
    if (protection == 0) {
        errno = EINVAL;
        return -1;
    }
    if (!VirtualProtect(address, length, protection, &old_protection)) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

#endif /* HYBRIS_WINDOWS_SYS_MMAN_H */

/* UCRT/MinGW expose locale objects as _locale_t, not POSIX locale_t. */
#if defined(_MSC_VER) || defined(__MINGW32__)
typedef _locale_t locale_t;
#endif
#ifndef LC_COLLATE_MASK
#define LC_COLLATE_MASK (1 << LC_COLLATE)
#define LC_CTYPE_MASK   (1 << LC_CTYPE)
#define LC_MONETARY_MASK (1 << LC_MONETARY)
#define LC_NUMERIC_MASK (1 << LC_NUMERIC)
#define LC_TIME_MASK    (1 << LC_TIME)
#ifdef LC_MESSAGES
#define LC_MESSAGES_MASK (1 << LC_MESSAGES)
#else
#define LC_MESSAGES_MASK 0
#endif
#define LC_ALL_MASK (LC_COLLATE_MASK | LC_CTYPE_MASK | LC_MONETARY_MASK | \
                    LC_NUMERIC_MASK | LC_TIME_MASK | LC_MESSAGES_MASK)
#endif
#ifndef LC_GLOBAL_LOCALE
#define LC_GLOBAL_LOCALE ((locale_t)-1L)
#endif

static inline locale_t hybris_windows_newlocale(int category_mask,
                                                 const char *locale,
                                                 locale_t base) {
    int category;
    _locale_t result;

    if (locale == NULL) {
        errno = EINVAL;
        return (locale_t)0;
    }
    if (base != (locale_t)0) {
        errno = ENOSYS;
        return (locale_t)0;
    }
    if (category_mask == LC_ALL_MASK) {
        category = LC_ALL;
    } else if (category_mask == LC_COLLATE_MASK) {
        category = LC_COLLATE;
    } else if (category_mask == LC_CTYPE_MASK) {
        category = LC_CTYPE;
    } else if (category_mask == LC_MONETARY_MASK) {
        category = LC_MONETARY;
    } else if (category_mask == LC_NUMERIC_MASK) {
        category = LC_NUMERIC;
    } else if (category_mask == LC_TIME_MASK) {
        category = LC_TIME;
    } else {
        errno = ENOSYS;
        return (locale_t)0;
    }

    result = _create_locale(category, locale);
    if (result == NULL) {
        errno = ENOENT;
        return (locale_t)0;
    }
    return (locale_t)result;
}
static inline void hybris_windows_freelocale(locale_t locobj) {
    if (locobj != (locale_t)0 && locobj != LC_GLOBAL_LOCALE)
        _free_locale((_locale_t)locobj);
}
static inline locale_t hybris_windows_duplocale(locale_t locobj) {
    (void)locobj;
    errno = ENOSYS;
    return (locale_t)0;
}
static inline locale_t hybris_windows_uselocale(locale_t newloc) {
    (void)newloc;
    errno = ENOSYS;
    return (locale_t)0;
}
static inline double hybris_windows_strtod_l(const char *nptr, char **endptr,
                                             locale_t locobj) {
    if (locobj == (locale_t)0 || locobj == LC_GLOBAL_LOCALE) {
        errno = EINVAL;
        if (endptr != NULL)
            *endptr = (char *)nptr;
        return 0.0;
    }
    return _strtod_l(nptr, endptr, (_locale_t)locobj);
}

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
#define posix_memalign hybris_windows_posix_memalign
#define ttyname hybris_windows_ttyname
#define ptsname hybris_windows_ptsname
#define mmap hybris_windows_mmap
#define mmap64 hybris_windows_mmap64
#define munmap hybris_windows_munmap
#define mprotect hybris_windows_mprotect
#define newlocale hybris_windows_newlocale
#define freelocale hybris_windows_freelocale
#define duplocale hybris_windows_duplocale
#define uselocale hybris_windows_uselocale
#define strtod_l hybris_windows_strtod_l
#if defined(__MINGW32__)
#define aligned_alloc hybris_windows_aligned_alloc
#endif

#endif
#endif
