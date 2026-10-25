/*
 * windows_hook_table.c — minimal hybris hook table for Windows DRM loading.
 *
 * Provides hybris_get_hooked_symbol() with the symbols Apple's Android DRM
 * libraries actually need from the host.  Compiled on Windows only.
 *
 * NOT a replacement for the full hooks.c; it covers only what the Android
 * DRM lib chain (libCoreFP → libstoreservicescore → libandroidappmusic) needs.
 */

#include "windows_core_compat.h"

#include <windows.h>
#include <hybris/common/dlfcn.h>
#include <hybris/common/hooks.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <math.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>

/* Win32 pthread wrappers (static functions). */
#include "hooks_win32.c"

/* User-supplied fallback callback from windows_core_hooks.c. */
extern hybris_hook_cb _hybris_win32_user_hook_cb;

/* Android dl* functions from windows_core_hooks.c. */
extern void *android_dlopen(const char *, int);
extern void *android_dlsym(void *, const char *);
extern int   android_dlclose(void *);
extern char *android_dlerror(void);
extern int   android_dladdr(const void *, void *);
extern int   android_dl_iterate_phdr(int (*)(void *, size_t, void *), void *);

/* __errno_location: glibc accessor for errno — map to MSVCRT _errno(). */
static int *_win32_errno_location(void) { return _errno(); }

/* Android log stubs (liblog.so). */
static int _win32_android_log_print(int prio, const char *tag, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    return 0;
}
static int _win32_android_log_buf_print(int buf, int prio, const char *tag,
                                         const char *fmt, ...) {
    (void)buf;
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr); return 0;
}
static int _win32___android_log_is_loggable(int p, const char *t, int d) {
    (void)p; (void)t; (void)d; return 1;
}

/* pthread timedwait variants not in older MinGW. */
#ifndef HAVE_PTHREAD_MUTEX_TIMEDLOCK
static int _win32_pthread_mutex_timedlock(pthread_mutex_t *m,
                                           const struct timespec *ts) {
    (void)ts; return pthread_mutex_lock(m);
}
#else
#define _win32_pthread_mutex_timedlock pthread_mutex_timedlock
#endif

struct _w32_hook { const char *name; void *fn; };

#define H(sym)        { #sym,  (void *)(sym) }
#define HW(sym)       { #sym,  (void *)(_hybris_win32_##sym) }
#define HA(sym, fn)   { #sym,  (void *)(fn) }

static const struct _w32_hook win32_hooks[] = {
    /* ── dlopen / dlsym family ──────────────────────────────────────── */
    HA(dlopen,               android_dlopen),
    HA(dlsym,                android_dlsym),
    HA(dlclose,              android_dlclose),
    HA(dlerror,              android_dlerror),
    HA(dladdr,               android_dladdr),
    HA(dl_iterate_phdr,      android_dl_iterate_phdr),

    /* ── pthread lifecycle ───────────────────────────────────────────── */
    HW(pthread_atfork),
    HA(pthread_create,       pthread_create),
    HA(pthread_kill,         pthread_kill),
    HW(pthread_exit),
    HW(pthread_join),
    HW(pthread_detach),
    HW(pthread_self),
    HW(pthread_equal),
    HW(pthread_getschedparam),
    HW(pthread_setschedparam),

    /* ── pthread mutex ───────────────────────────────────────────────── */
    HA(pthread_mutex_init,         pthread_mutex_init),
    HA(pthread_mutex_destroy,      pthread_mutex_destroy),
    HA(pthread_mutex_lock,         pthread_mutex_lock),
    HA(pthread_mutex_unlock,       pthread_mutex_unlock),
    HA(pthread_mutex_trylock,      pthread_mutex_trylock),
    HA(pthread_mutex_timedlock,    _win32_pthread_mutex_timedlock),
    HW(pthread_mutexattr_init),
    HW(pthread_mutexattr_destroy),
    HW(pthread_mutexattr_gettype),
    HW(pthread_mutexattr_settype),
    HW(pthread_mutexattr_getpshared),
    HW(pthread_mutexattr_setpshared),
    HW(pthread_mutexattr_getprotocol),
    HW(pthread_mutexattr_setprotocol),

    /* ── pthread cond ────────────────────────────────────────────────── */
    HA(pthread_cond_init,          pthread_cond_init),
    HA(pthread_cond_destroy,       pthread_cond_destroy),
    HA(pthread_cond_broadcast,     pthread_cond_broadcast),
    HA(pthread_cond_signal,        pthread_cond_signal),
    HA(pthread_cond_wait,          pthread_cond_wait),
    HA(pthread_cond_timedwait,     pthread_cond_timedwait),
    HW(pthread_condattr_init),
    HW(pthread_condattr_destroy),
    HW(pthread_condattr_getpshared),
    HW(pthread_condattr_setpshared),
    HW(pthread_condattr_getclock),
    HW(pthread_condattr_setclock),

    /* ── pthread key / once ──────────────────────────────────────────── */
    HW(pthread_key_create),
    HW(pthread_key_delete),
    HA(pthread_getspecific,        pthread_getspecific),
    HW(pthread_setspecific),
    HW(pthread_once),
    HW(pthread_getname_np),

    /* ── pthread attr ────────────────────────────────────────────────── */
    HA(pthread_attr_init,              pthread_attr_init),
    HA(pthread_attr_destroy,           pthread_attr_destroy),
    HA(pthread_attr_setdetachstate,    pthread_attr_setdetachstate),
    HA(pthread_attr_getdetachstate,    pthread_attr_getdetachstate),
    HA(pthread_attr_setschedpolicy,    pthread_attr_setschedpolicy),
    HA(pthread_attr_getschedpolicy,    pthread_attr_getschedpolicy),
    HA(pthread_attr_setschedparam,     pthread_attr_setschedparam),
    HA(pthread_attr_getschedparam,     pthread_attr_getschedparam),
    HA(pthread_attr_setstacksize,      pthread_attr_setstacksize),
    HA(pthread_attr_getstacksize,      pthread_attr_getstacksize),

    /* ── pthread rwlock ──────────────────────────────────────────────── */
    HA(pthread_rwlock_init,        pthread_rwlock_init),
    HA(pthread_rwlock_destroy,     pthread_rwlock_destroy),
    HA(pthread_rwlock_rdlock,      pthread_rwlock_rdlock),
    HA(pthread_rwlock_wrlock,      pthread_rwlock_wrlock),
    HA(pthread_rwlock_unlock,      pthread_rwlock_unlock),
    HA(pthread_rwlock_tryrdlock,   pthread_rwlock_tryrdlock),
    HA(pthread_rwlock_trywrlock,   pthread_rwlock_trywrlock),

    /* ── memory ──────────────────────────────────────────────────────── */
    H(malloc), H(free), H(calloc), H(realloc),
    H(memcpy), H(memmove), H(memset), H(memcmp), H(memchr),

    /* ── string ──────────────────────────────────────────────────────── */
    H(strcmp), H(strncmp), H(strcasecmp), H(strncasecmp),
    H(strcpy), H(strncpy), H(strcat), H(strncat),
    H(strlen), H(strchr), H(strrchr), H(strstr), H(strdup),
    H(strtol), H(strtoul), H(strtoll), H(strtoull),
    H(strtod), H(strtof), H(atoi), H(atol), H(atoll), H(atof),

    /* ── stdio ───────────────────────────────────────────────────────── */
    H(printf), H(fprintf), H(sprintf), H(snprintf),
    H(vprintf), H(vfprintf), H(vsprintf), H(vsnprintf),
    H(scanf), H(sscanf), H(fscanf),
    H(fopen), H(fclose), H(fread), H(fwrite),
    H(fseek), H(ftell), H(rewind), H(fflush),
    H(feof), H(ferror), H(clearerr),
    H(fgets), H(fputs), H(fputc), H(fgetc),
    H(puts), H(putchar), H(getchar),
    H(fileno), H(setvbuf),
    HA(flockfile,   _lock_file),
    HA(funlockfile, _unlock_file),
    HA(ftrylockfile, _lock_file),  /* noop trylock — always succeeds */

    /* ── process / misc ──────────────────────────────────────────────── */
    H(abort), H(exit),
    HA(_exit,   _exit),
    H(getenv),
    HA(clearenv, (void *)(intptr_t)0),  /* noop stub — return NULL */
    H(qsort), H(bsearch),
    H(time), H(clock),

    /* ── errno ───────────────────────────────────────────────────────── */
    HA(__errno_location, _win32_errno_location),

    /* ── math ────────────────────────────────────────────────────────── */
    H(sin), H(cos), H(tan), H(asin), H(acos), H(atan), H(atan2),
    H(sinh), H(cosh), H(tanh),
    H(sqrt), H(pow), H(exp), H(log), H(log2), H(log10),
    H(fabs), H(floor), H(ceil), H(round), H(fmod),
    H(sinf), H(cosf), H(tanf), H(sqrtf), H(powf), H(expf),
    H(logf), H(log2f), H(log10f), H(fabsf), H(floorf), H(ceilf),

    /* ── Android log (liblog.so) ─────────────────────────────────────── */
    HA(__android_log_print,      _win32_android_log_print),
    HA(__android_log_buf_print,  _win32_android_log_buf_print),
    HA(__android_log_is_loggable, _win32___android_log_is_loggable),
    HA(__android_log_write,      _win32_android_log_print),

    { NULL, NULL }
};

void *hybris_get_hooked_symbol(const char *sym, const char *requester)
{
    if (!sym) return NULL;
    for (int i = 0; win32_hooks[i].name; i++)
        if (strcmp(sym, win32_hooks[i].name) == 0)
            return win32_hooks[i].fn;
    if (_hybris_win32_user_hook_cb)
        return _hybris_win32_user_hook_cb(sym, requester);
    return NULL;
}
