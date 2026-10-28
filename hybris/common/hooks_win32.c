/*
 * hooks_win32.c — Windows implementations for Android symbols that hooks.c
 * marks as HOOK_DIRECT_NO_DEBUG (which returns NULL on Windows).
 *
 * Included by hooks.c via #include when _WIN32 is defined, so all of these
 * are static and local to hooks.c's translation unit.
 *
 * Naming: _hybris_win32_<symbol> — thin wrappers around MinGW winpthread.
 */

#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

/* ── pthread_atfork ──────────────────────────────────────────────────────────*/
/* fork() does not exist on Windows; atfork handlers are never needed. */
static __attribute__((sysv_abi)) int _hybris_win32_pthread_atfork(void (*prepare)(void),
                                         void (*parent)(void),
                                         void (*child)(void))
{
    (void)prepare; (void)parent; (void)child;
    return 0;
}

/* ── pthread lifecycle ───────────────────────────────────────────────────────*/
static __attribute__((sysv_abi)) void _hybris_win32_pthread_exit(void *retval)
{
    pthread_exit(retval);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_join(pthread_t thread, void **retval)
{
    return pthread_join(thread, retval);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_detach(pthread_t thread)
{
    return pthread_detach(thread);
}

static __attribute__((sysv_abi)) pthread_t _hybris_win32_pthread_self(void)
{
    return pthread_self();
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_equal(pthread_t t1, pthread_t t2)
{
    return pthread_equal(t1, t2);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_once(pthread_once_t *once_control,
                                       void (*init_routine)(void))
{
    return pthread_once(once_control, init_routine);
}

/* ── pthread key ─────────────────────────────────────────────────────────────*/
static __attribute__((sysv_abi)) int _hybris_win32_pthread_key_create(pthread_key_t *key,
                                              void (*destructor)(void *))
{
    /* The guest destructor is a SysV-ABI function pointer.  winpthread calls
     * TLS destructors using the host Microsoft x64 callback ABI, which passes
     * the value in RCX instead of RDI and corrupts the guest callback's first
     * argument.  Keep the key usable but do not register an ABI-incompatible
     * host callback; cleanup is deferred until a callback bridge is available. */
    (void)destructor;
    return pthread_key_create(key, NULL);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_key_delete(pthread_key_t key)
{
    return pthread_key_delete(key);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_setspecific(pthread_key_t key,
                                              const void *value)
{
    return pthread_setspecific(key, value);
}

/* ── pthread sched ───────────────────────────────────────────────────────────*/
static __attribute__((sysv_abi)) int _hybris_win32_pthread_getschedparam(pthread_t thread, int *policy,
                                                struct sched_param *param)
{
    return pthread_getschedparam(thread, policy, param);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_setschedparam(pthread_t thread, int policy,
                                                const struct sched_param *param)
{
    return pthread_setschedparam(thread, policy, param);
}

/* ── pthread_mutexattr ───────────────────────────────────────────────────────*/
static __attribute__((sysv_abi)) int _hybris_win32_pthread_mutexattr_init(pthread_mutexattr_t *attr)
{
    return pthread_mutexattr_init(attr);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_mutexattr_destroy(pthread_mutexattr_t *attr)
{
    return pthread_mutexattr_destroy(attr);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_mutexattr_gettype(const pthread_mutexattr_t *attr,
                                                    int *kind)
{
    return pthread_mutexattr_gettype(attr, kind);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_mutexattr_settype(pthread_mutexattr_t *attr,
                                                    int kind)
{
    return pthread_mutexattr_settype(attr, kind);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr,
                                                       int *pshared)
{
    (void)attr;
    if (pshared) *pshared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_mutexattr_setpshared(pthread_mutexattr_t *attr,
                                                       int pshared)
{
    (void)attr; (void)pshared;
    return 0;
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_mutexattr_getprotocol(const pthread_mutexattr_t *attr,
                                                        int *protocol)
{
    (void)attr;
    if (protocol) *protocol = 0; /* PTHREAD_PRIO_NONE */
    return 0;
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr,
                                                        int protocol)
{
    (void)attr; (void)protocol;
    return 0;
}

/* ── pthread_condattr ────────────────────────────────────────────────────────*/
static __attribute__((sysv_abi)) int _hybris_win32_pthread_condattr_init(pthread_condattr_t *attr)
{
    return pthread_condattr_init(attr);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_condattr_destroy(pthread_condattr_t *attr)
{
    return pthread_condattr_destroy(attr);
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_condattr_getpshared(const pthread_condattr_t *attr,
                                                      int *pshared)
{
    (void)attr;
    if (pshared) *pshared = PTHREAD_PROCESS_PRIVATE;
    return 0;
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_condattr_setpshared(pthread_condattr_t *attr,
                                                      int pshared)
{
    (void)attr; (void)pshared;
    return 0;
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_condattr_getclock(const pthread_condattr_t *attr,
                                                    clockid_t *clock_id)
{
#if defined(PTHREAD_COND_INITIALIZER) && defined(_POSIX_TIMEOUTS)
    return pthread_condattr_getclock(attr, clock_id);
#else
    (void)attr;
    if (clock_id) *clock_id = CLOCK_REALTIME;
    return 0;
#endif
}

static __attribute__((sysv_abi)) int _hybris_win32_pthread_condattr_setclock(pthread_condattr_t *attr,
                                                    clockid_t clock_id)
{
#if defined(PTHREAD_COND_INITIALIZER) && defined(_POSIX_TIMEOUTS)
    return pthread_condattr_setclock(attr, clock_id);
#else
    (void)attr; (void)clock_id;
    return 0;
#endif
}

/* ── pthread_getname_np ──────────────────────────────────────────────────────*/
static __attribute__((sysv_abi)) int _hybris_win32_pthread_getname_np(pthread_t thread, char *buf,
                                             size_t buflen)
{
    (void)thread;
    if (buf && buflen > 0) buf[0] = '\0';
    return 0;
}

/* ── HOOK_TO entries used by the overridden hooks_common[] table ─────────────*/
/* These macros are referenced in the hooks_common[] section of hooks.c via   */
/* HOOK_WIN32(sym) → HOOK_TO(sym, _hybris_win32_##sym).                       */
