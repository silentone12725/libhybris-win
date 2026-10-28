/*
 * windows_hook_table.c — hybris hook table for Windows DRM loading.
 *
 * Provides hybris_get_hooked_symbol() with the symbols Apple's Android DRM
 * libraries need from the host.  Apple's .so code is System V AMD64; the host
 * (ucrtbase/winpthread) is Windows x64.  Every hook that takes pointer/integer
 * args must be sysv_abi so (a) args are read from the right registers and
 * (b) register spills land in the callee frame, not the SysV caller's absent
 * 32-byte shadow space.  bionic's pthread_mutex_t/cond_t/rwlock_t also differ
 * from winpthread's, so those are reimplemented over the bionic int32 layout.
 *
 * Reconstructed after a build-VM wipe from the surviving 220-line base plus the
 * recovered fixes (#1 pthread, #3 host-libc, #6 mmap, #7 win32).  See
 * recovery/README.md.
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
#include <stdint.h>
#include <malloc.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <direct.h>
#include <time.h>

/* Win32 pthread wrappers (static functions). */
#include "hooks_win32.c"

/* User-supplied fallback callback from windows_core_hooks.c. */
extern hybris_hook_cb _hybris_win32_user_hook_cb;
extern void *hybris_guest_thread_call(void *, void *);

/* Android dl* functions from windows_core_hooks.c (Windows ABI). */
extern void *android_dlopen(const char *, int);
extern void *android_dlsym(void *, const char *);
extern int   android_dlclose(void *);

/* Winsock shim (hybris_net.c, sysv_abi). Socket fds live in a synthetic range
 * so read/write/close/fcntl can route them to the socket path. */
extern int  __attribute__((sysv_abi)) _net_is_fd(int fd);
extern long __attribute__((sysv_abi)) _net_read(int, void *, size_t);
extern long __attribute__((sysv_abi)) _net_write(int, const void *, size_t);
extern int  __attribute__((sysv_abi)) _net_close(int);
extern int  __attribute__((sysv_abi)) _net_fcntl(int, int, int);
extern int  __attribute__((sysv_abi)) _net_socket(int, int, int);
extern int  __attribute__((sysv_abi)) _net_connect(int, const void *, int);
extern long __attribute__((sysv_abi)) _net_send(int, const void *, size_t, int);
extern long __attribute__((sysv_abi)) _net_recv(int, void *, size_t, int);
extern long __attribute__((sysv_abi)) _net_sendto(int, const void *, size_t, int, const void *, int);
extern long __attribute__((sysv_abi)) _net_recvfrom(int, void *, size_t, int, void *, int *);
extern int  __attribute__((sysv_abi)) _net_shutdown(int, int);
extern int  __attribute__((sysv_abi)) _net_getpeername(int, void *, int *);
extern int  __attribute__((sysv_abi)) _net_getsockname(int, void *, int *);
extern int  __attribute__((sysv_abi)) _net_setsockopt(int, int, int, const void *, int);
extern int  __attribute__((sysv_abi)) _net_getsockopt(int, int, int, void *, int *);
extern int  __attribute__((sysv_abi)) _net_ioctl(int, unsigned long, void *);
extern int  __attribute__((sysv_abi)) _net_poll(void *, unsigned long, int);
extern int  __attribute__((sysv_abi)) _net_getaddrinfo(const char *, const char *, const void *, void **);
extern void __attribute__((sysv_abi)) _net_freeaddrinfo(void *);
extern int  __attribute__((sysv_abi)) _net_inet_pton(int, const char *, void *);
extern const char *__attribute__((sysv_abi)) _net_inet_ntop(int, const void *, char *, unsigned int);
extern int  __attribute__((sysv_abi)) _net_bind(int, const void *, int);
extern int  __attribute__((sysv_abi)) _net_listen(int, int);
extern int  __attribute__((sysv_abi)) _net_accept(int, void *, int *);
extern int  __attribute__((sysv_abi)) _net_socketpair(int, int, int, int *);
extern unsigned int __attribute__((sysv_abi)) _net_if_nametoindex(const char *);
extern int  __attribute__((sysv_abi)) _net_epoll_create(int);
extern int  __attribute__((sysv_abi)) _net_epoll_create1(int);
extern int  __attribute__((sysv_abi)) _net_epoll_ctl(int, int, int, const void *);
extern int  __attribute__((sysv_abi)) _net_epoll_wait(int, void *, int, int);
extern int  __attribute__((sysv_abi)) _net_ppoll(void *, unsigned long, const void *, const void *);
extern int  __attribute__((sysv_abi)) _net_select(int, void *, void *, void *, const void *);
extern int  __attribute__((sysv_abi)) _net_eventfd(unsigned int, int);
extern int  __attribute__((sysv_abi)) _net_eventfd_write(int, unsigned long long);
extern int  __attribute__((sysv_abi)) _net_timerfd_create(int, int);
extern int  __attribute__((sysv_abi)) _net_timerfd_settime(int, int, const void *, void *);
extern char *android_dlerror(void);
extern int   android_dladdr(const void *, void *);
extern int   android_dl_iterate_phdr(int (*)(void *, size_t, void *), void *);

/* ── bionic pthread_mutex (int32 spinlock) ──────────────────────────────────
 * bionic pthread_mutex_t is a 4-byte atomic int (0=unlocked, 1=locked), not
 * winpthread's heap-pointer handle, so reimplement it directly. */
/* bionic pthread_mutex types include PTHREAD_MUTEX_RECURSIVE, and the DRM code
 * locks some mutexes re-entrantly on one thread. A bare int32 lock word can't
 * express recursion, so treat every mutex as recursive: the int32 is the
 * cross-thread lock bit, and a side table records the owning thread and the
 * recursion depth. (Making a normal mutex recursive is harmless: it is locked
 * and unlocked exactly once, depth 1.) */
static CRITICAL_SECTION g_mtab_cs;
static volatile long    g_mtab_cs_state = 0;  /* 0=uninit 1=initing 2=ready */
static struct { void *m; unsigned long owner; int depth; } g_mtab[512];
static int g_mtab_n = 0;
static void _mtab_ready(void){
    /* The first mutex use happens during single-threaded init, before any
     * pthread_create, so a plain guard is sufficient to initialize the CS. */
    if (g_mtab_cs_state == 2) return;
    if (g_mtab_cs_state == 0){ g_mtab_cs_state = 1; InitializeCriticalSection(&g_mtab_cs); g_mtab_cs_state = 2; }
    else { while (g_mtab_cs_state != 2) SwitchToThread(); }
}
static int _mtab_find(void *m){ for (int i=0;i<g_mtab_n;i++) if (g_mtab[i].m==m) return i; return -1; }
static int __attribute__((sysv_abi)) _bionic_mutex_init(volatile int32_t *m, const void *attr)
{ if (!m) return EINVAL; (void)attr; __atomic_store_n(m, 0, __ATOMIC_RELEASE);
  _mtab_ready(); EnterCriticalSection(&g_mtab_cs); int i=_mtab_find((void*)m);
  if(i>=0){ g_mtab[i].owner=0; g_mtab[i].depth=0; } LeaveCriticalSection(&g_mtab_cs); return 0; }
static int __attribute__((sysv_abi)) _bionic_mutex_destroy(volatile int32_t *m)
{ if (!m) return 0; _mtab_ready(); EnterCriticalSection(&g_mtab_cs); int i=_mtab_find((void*)m);
  if(i>=0){ g_mtab[i]=g_mtab[--g_mtab_n]; } LeaveCriticalSection(&g_mtab_cs); return 0; }
static int __attribute__((sysv_abi)) _bionic_mutex_lock(volatile int32_t *m)
{
    if (!m) return EINVAL;
    _mtab_ready();
    unsigned long me = GetCurrentThreadId();
    for (;;) {
        EnterCriticalSection(&g_mtab_cs);
        int i = _mtab_find((void*)m);
        if (i >= 0 && g_mtab[i].owner == me){ g_mtab[i].depth++; LeaveCriticalSection(&g_mtab_cs); return 0; }
        int32_t old = 0;
        if (__atomic_compare_exchange_n(m, &old, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)){
            if (i < 0 && g_mtab_n < 512){ i = g_mtab_n++; g_mtab[i].m = (void*)m; }
            if (i >= 0){ g_mtab[i].owner = me; g_mtab[i].depth = 1; }
            LeaveCriticalSection(&g_mtab_cs); return 0;
        }
        LeaveCriticalSection(&g_mtab_cs);
        SwitchToThread();
    }
}
static int __attribute__((sysv_abi)) _bionic_mutex_trylock(volatile int32_t *m)
{
    if (!m) return EINVAL;
    _mtab_ready();
    unsigned long me = GetCurrentThreadId();
    EnterCriticalSection(&g_mtab_cs);
    int i = _mtab_find((void*)m);
    if (i >= 0 && g_mtab[i].owner == me){ g_mtab[i].depth++; LeaveCriticalSection(&g_mtab_cs); return 0; }
    int32_t old = 0; int rc = EBUSY;
    if (__atomic_compare_exchange_n(m, &old, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)){
        if (i < 0 && g_mtab_n < 512){ i = g_mtab_n++; g_mtab[i].m = (void*)m; }
        if (i >= 0){ g_mtab[i].owner = me; g_mtab[i].depth = 1; } rc = 0;
    }
    LeaveCriticalSection(&g_mtab_cs); return rc;
}
static int __attribute__((sysv_abi)) _bionic_mutex_unlock(volatile int32_t *m)
{
    if (!m) return EINVAL;
    _mtab_ready();
    EnterCriticalSection(&g_mtab_cs);
    int i = _mtab_find((void*)m);
    if (i >= 0 && g_mtab[i].depth > 0){
        if (--g_mtab[i].depth == 0){ g_mtab[i].owner = 0; __atomic_store_n(m, 0, __ATOMIC_RELEASE); }
    } else {
        __atomic_store_n(m, 0, __ATOMIC_RELEASE);  /* was locked without a table entry */
    }
    LeaveCriticalSection(&g_mtab_cs); return 0;
}
static int __attribute__((sysv_abi)) _bionic_mutex_timedlock(volatile int32_t *m, const struct timespec *ts)
{ (void)ts; return _bionic_mutex_lock(m); }

/* bionic pthread_once_t is int32: 0=not-done, 1=in-progress, 2=done. */
static int __attribute__((sysv_abi)) _bionic_pthread_once(volatile int32_t *once, void (*fn)(void))
{
    int32_t old;
    if (!once) return EINVAL;
    if (__atomic_load_n(once, __ATOMIC_ACQUIRE) == 2) return 0;
    for (;;) {
        old = 0;
        if (__atomic_compare_exchange_n(once, &old, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
            ((void (__attribute__((sysv_abi)) *)(void))fn)();
            __atomic_store_n(once, 2, __ATOMIC_RELEASE);
            return 0;
        }
        if (old == 2) return 0;
        SwitchToThread();
    }
}

/* ── bionic pthread_cond over CRITICAL_SECTION/CONDITION_VARIABLE ────────────
 * bionic cond_t is 48B inline; store an 8-byte impl pointer in it.  cond_wait
 * releases/reacquires the bionic spinlock mutex around the wait. */
typedef struct _bionic_cond_impl { CRITICAL_SECTION cs; CONDITION_VARIABLE cv; } _bionic_cond_impl_t;
/* libc++'s std::condition_variable is statically zero-initialized
 * (PTHREAD_COND_INITIALIZER) and never passes through pthread_cond_init, so the
 * impl pointer stored in the bionic cond_t is 0 on first use. Create it lazily
 * under g_mtab_cs instead of failing with EINVAL (which made cond_wait throw
 * "condition_variable wait failed: Invalid argument"). */
static _bionic_cond_impl_t *_cond_get(void *cond)
{ if (!cond) return NULL; _mtab_ready(); EnterCriticalSection(&g_mtab_cs);
  _bionic_cond_impl_t *d = (_bionic_cond_impl_t *)(*(uintptr_t *)cond);
  if (!d){ d = (_bionic_cond_impl_t *)malloc(sizeof *d);
    if (d){ InitializeCriticalSection(&d->cs); InitializeConditionVariable(&d->cv); *(uintptr_t *)cond = (uintptr_t)d; } }
  LeaveCriticalSection(&g_mtab_cs); return d; }
static int __attribute__((sysv_abi)) _bionic_cond_init(void *cond, const void *attr)
{ if (!cond) return EINVAL; (void)attr; return _cond_get(cond) ? 0 : ENOMEM; }
static int __attribute__((sysv_abi)) _bionic_cond_destroy(void *cond)
{ if (!cond) return EINVAL; _bionic_cond_impl_t *d = (_bionic_cond_impl_t *)(*(uintptr_t *)cond);
  if (!d) return 0; DeleteCriticalSection(&d->cs); free(d); *(uintptr_t *)cond = 0; return 0; }
/* Diagnostics (condition-variable, futex and libcurl tracing) are off unless ADAM_WTRACE is set. */
static int _wtrace_on(void)
{
    static volatile int v = -1;
    if (v < 0) v = getenv("ADAM_WTRACE") != NULL;
    return v;
}
static volatile long g_wtrace_n;
static int __attribute__((sysv_abi)) _bionic_cond_signal(void *cond)
{ _bionic_cond_impl_t *d = _cond_get(cond); if (!d) return EINVAL; if (_wtrace_on() && __atomic_load_n(&g_wtrace_n, __ATOMIC_RELAXED) < 3000) { fprintf(stderr, "[wtrace] cond_signal tid=%lu cond=%p ra=%p\n", GetCurrentThreadId(), cond, __builtin_return_address(0)); fflush(stderr); __atomic_fetch_add(&g_wtrace_n, 1, __ATOMIC_RELAXED); } WakeConditionVariable(&d->cv); return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_broadcast(void *cond)
{ _bionic_cond_impl_t *d = _cond_get(cond); if (!d) return EINVAL; if (_wtrace_on() && __atomic_load_n(&g_wtrace_n, __ATOMIC_RELAXED) < 3000) { fprintf(stderr, "[wtrace] cond_broadcast tid=%lu cond=%p ra=%p\n", GetCurrentThreadId(), cond, __builtin_return_address(0)); fflush(stderr); __atomic_fetch_add(&g_wtrace_n, 1, __ATOMIC_RELAXED); } WakeAllConditionVariable(&d->cv); return 0; }
static volatile long g_wtrace_n = 0;
#define WTRACE(...) do { if (_wtrace_on() && __atomic_fetch_add(&g_wtrace_n, 1, __ATOMIC_RELAXED) < 3000) { fprintf(stderr, __VA_ARGS__); fflush(stderr); } } while (0)
static int __attribute__((sysv_abi)) _bionic_cond_wait(void *cond, volatile int32_t *m)
{ if (!m) return EINVAL; _bionic_cond_impl_t *d = _cond_get(cond);
  if (!d) return EINVAL; WTRACE("[wtrace] cond_wait tid=%lu cond=%p ENTER\n", GetCurrentThreadId(), cond);
  _bionic_mutex_unlock(m); EnterCriticalSection(&d->cs);
  SleepConditionVariableCS(&d->cv, &d->cs, INFINITE); LeaveCriticalSection(&d->cs);
  _bionic_mutex_lock(m); WTRACE("[wtrace] cond_wait tid=%lu cond=%p WOKE\n", GetCurrentThreadId(), cond); return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_timedwait(void *cond, volatile int32_t *m, const struct timespec *ts)
{ if (!m) return EINVAL; _bionic_cond_impl_t *d = _cond_get(cond);
  if (!d) return EINVAL; DWORD ms = INFINITE;
  if (ts) { struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
    long long diff = ((long long)ts->tv_sec - now.tv_sec) * 1000LL + ((long long)ts->tv_nsec - now.tv_nsec) / 1000000LL;
    if (diff <= 0) { WTRACE("[wtrace] cond_timedwait tid=%lu cond=%p deadline already past diff=%lld (sec=%lld nsec=%lld)\n", GetCurrentThreadId(), cond, diff, (long long)ts->tv_sec, (long long)ts->tv_nsec); return ETIMEDOUT; }
    ms = (DWORD)diff; }
  WTRACE("[wtrace] cond_timedwait tid=%lu cond=%p ms=%lu ENTER\n", GetCurrentThreadId(), cond, (unsigned long)ms);
  _bionic_mutex_unlock(m); EnterCriticalSection(&d->cs);
  BOOL ok = SleepConditionVariableCS(&d->cv, &d->cs, ms); LeaveCriticalSection(&d->cs);
  _bionic_mutex_lock(m); WTRACE("[wtrace] cond_timedwait tid=%lu cond=%p %s\n", GetCurrentThreadId(), cond, ok ? "WOKE" : "TIMEDOUT"); return ok ? 0 : ETIMEDOUT; }

/* ── rwlock / attr / create (call-through / trampoline) ─────────────────── */
static int __attribute__((sysv_abi)) _bionic_rwlock_init(void *rw, const void *a){(void)a;return pthread_rwlock_init((pthread_rwlock_t*)rw,NULL);}
static int __attribute__((sysv_abi)) _bionic_rwlock_destroy(void *rw){return pthread_rwlock_destroy((pthread_rwlock_t*)rw);}
static int __attribute__((sysv_abi)) _bionic_rwlock_rdlock(void *rw){return pthread_rwlock_rdlock((pthread_rwlock_t*)rw);}
static int __attribute__((sysv_abi)) _bionic_rwlock_wrlock(void *rw){return pthread_rwlock_wrlock((pthread_rwlock_t*)rw);}
static int __attribute__((sysv_abi)) _bionic_rwlock_unlock(void *rw){return pthread_rwlock_unlock((pthread_rwlock_t*)rw);}
static int __attribute__((sysv_abi)) _bionic_rwlock_tryrdlock(void *rw){return pthread_rwlock_tryrdlock((pthread_rwlock_t*)rw);}
static int __attribute__((sysv_abi)) _bionic_rwlock_trywrlock(void *rw){return pthread_rwlock_trywrlock((pthread_rwlock_t*)rw);}
static int __attribute__((sysv_abi)) _bionic_attr_init(void *a){ if(a)memset(a,0,sizeof(pthread_attr_t)); return pthread_attr_init((pthread_attr_t*)a);}
static int __attribute__((sysv_abi)) _bionic_attr_destroy(void *a){return pthread_attr_destroy((pthread_attr_t*)a);}
static int __attribute__((sysv_abi)) _bionic_attr_setdetachstate(void *a,int s){return pthread_attr_setdetachstate((pthread_attr_t*)a,s);}
static int __attribute__((sysv_abi)) _bionic_attr_getdetachstate(void *a,int *s){return pthread_attr_getdetachstate((pthread_attr_t*)a,s);}
static int __attribute__((sysv_abi)) _bionic_attr_setstacksize(void *a,size_t z){return pthread_attr_setstacksize((pthread_attr_t*)a,z);}
static int __attribute__((sysv_abi)) _bionic_attr_getstacksize(void *a,size_t *z){return pthread_attr_getstacksize((pthread_attr_t*)a,z);}
static int __attribute__((sysv_abi)) _bionic_attr_setschedpolicy(void *a,int p){return pthread_attr_setschedpolicy((pthread_attr_t*)a,p);}
static int __attribute__((sysv_abi)) _bionic_attr_getschedpolicy(void *a,int *p){return pthread_attr_getschedpolicy((pthread_attr_t*)a,p);}
static int __attribute__((sysv_abi)) _bionic_attr_setschedparam(void *a,const void *pm){return pthread_attr_setschedparam((pthread_attr_t*)a,(const struct sched_param*)pm);}
static int __attribute__((sysv_abi)) _bionic_attr_getschedparam(void *a,void *pm){return pthread_attr_getschedparam((pthread_attr_t*)a,(struct sched_param*)pm);}
struct _bionic_thread_tramp { void *(*fn)(void *); void *arg; };
static void *_bionic_thread_entry(void *p){ struct _bionic_thread_tramp *t=(struct _bionic_thread_tramp*)p;
  void*(__attribute__((sysv_abi))*fn)(void*)=(void*(__attribute__((sysv_abi))*)(void*))t->fn; void*arg=t->arg; free(t);
  fprintf(stderr,"[thread-entry] fn=%p tid=%lu BEGIN\n",(void*)(uintptr_t)fn,(unsigned long)GetCurrentThreadId()); fflush(stderr);
   void *r=hybris_guest_thread_call((void *)(uintptr_t)fn, arg);
  fprintf(stderr,"[thread-entry] fn=%p tid=%lu END\n",(void*)(uintptr_t)fn,(unsigned long)GetCurrentThreadId()); fflush(stderr); return r; }
static int __attribute__((sysv_abi)) _bionic_pthread_create(void *tid,const void *attr,void *(*fn)(void*),void *arg)
{ (void)attr; fprintf(stderr,"[pthread_create] fn=%p\n",(void*)(uintptr_t)fn); struct _bionic_thread_tramp *t=(struct _bionic_thread_tramp*)malloc(sizeof *t); if(!t) return EAGAIN;
  t->fn=fn; t->arg=arg; int rc=pthread_create((pthread_t*)tid,NULL,_bionic_thread_entry,t); if(rc)free(t); return rc; }
static void *__attribute__((sysv_abi)) _bionic_getspecific(pthread_key_t k){return pthread_getspecific(k);}
static int __attribute__((sysv_abi)) _bionic_pthread_kill(pthread_t th,int sig){(void)th;(void)sig;return 0;}
static int __attribute__((sysv_abi)) _bionic_pthread_sigmask(int how,const void *set,void *old){(void)how;(void)set;(void)old;return 0;}

/* ── allocator (host, via sysv_abi) ─────────────────────────────────────── */
static void *__attribute__((sysv_abi)) _sysv_malloc(size_t n){return malloc(n);}
static void  __attribute__((sysv_abi)) _sysv_free(void *p){free(p);}
static void *__attribute__((sysv_abi)) _sysv_calloc(size_t a,size_t b){return calloc(a,b);}
static void *__attribute__((sysv_abi)) _sysv_realloc(void *p,size_t n){return realloc(p,n);}
static size_t __attribute__((sysv_abi)) _sysv_malloc_usable_size(void *p){return p?_msize(p):0;}
static void *__attribute__((sysv_abi)) _sysv_memalign(size_t al,size_t n){(void)al;return malloc(n);}
static int __attribute__((sysv_abi)) _sysv_posix_memalign(void **o,size_t al,size_t n){(void)al; if(!o)return 22; void*p=malloc(n); if(!p)return 12; *o=p; return 0;}
static void *__attribute__((sysv_abi)) _sysv_aligned_alloc(size_t al,size_t n){(void)al;return malloc(n);}

/* ── mem family (host, via sysv_abi) ────────────────────────────────────── */
static void *__attribute__((sysv_abi)) _sysv_memcpy(void *d,const void *s,size_t n){return memcpy(d,s,n);}
static void *__attribute__((sysv_abi)) _sysv_memmove(void *d,const void *s,size_t n){return memmove(d,s,n);}
static void *__attribute__((sysv_abi)) _sysv_memset(void *d,int c,size_t n){return memset(d,c,n);}
static int   __attribute__((sysv_abi)) _sysv_memcmp(const void *a,const void *b,size_t n){return memcmp(a,b,n);}
static void *__attribute__((sysv_abi)) _sysv_memchr(const void *p,int c,size_t n){return memchr(p,c,n);}

/* ── string family (host, via sysv_abi, with small-pointer guards) ──────── */
static int inline _lowp(const void *p){ return (uintptr_t)p < 0x10000u; }
static size_t __attribute__((sysv_abi)) _s_strlen(const char *s){ return _lowp(s)?0:strlen(s); }
static int    __attribute__((sysv_abi)) _s_strcmp(const char *a,const char *b){ if(_lowp(a)||_lowp(b))return (a==b)?0:(_lowp(a)?-1:1); return strcmp(a,b); }
static int    __attribute__((sysv_abi)) _s_strncmp(const char *a,const char *b,size_t n){ if(_lowp(a)||_lowp(b))return 0; return strncmp(a,b,n); }
static int    __attribute__((sysv_abi)) _s_strcasecmp(const char *a,const char *b){ if(_lowp(a)||_lowp(b))return 0; return _stricmp(a,b); }
static int    __attribute__((sysv_abi)) _s_strncasecmp(const char *a,const char *b,size_t n){ if(_lowp(a)||_lowp(b))return 0; return _strnicmp(a,b,n); }
static char  *__attribute__((sysv_abi)) _s_strcpy(char *d,const char *s){ return _lowp(s)?d:strcpy(d,s); }
static char  *__attribute__((sysv_abi)) _s_strncpy(char *d,const char *s,size_t n){ if(_lowp(s)){ if(n)memset(d,0,n); return d;} return strncpy(d,s,n); }
static char  *__attribute__((sysv_abi)) _s_strcat(char *d,const char *s){ return _lowp(s)?d:strcat(d,s); }
static char  *__attribute__((sysv_abi)) _s_strncat(char *d,const char *s,size_t n){ return _lowp(s)?d:strncat(d,s,n); }
static char  *__attribute__((sysv_abi)) _s_strchr(const char *s,int c){ return _lowp(s)?NULL:strchr(s,c); }
static char  *__attribute__((sysv_abi)) _s_strrchr(const char *s,int c){ return _lowp(s)?NULL:strrchr(s,c); }
static char  *__attribute__((sysv_abi)) _s_strstr(const char *h,const char *n){ if(_lowp(h)||_lowp(n))return NULL; return strstr(h,n); }
static char  *__attribute__((sysv_abi)) _s_strdup(const char *s){ return _lowp(s)?NULL:_strdup(s); }
static long      __attribute__((sysv_abi)) _s_strtol(const char *s,char **e,int b){ return _lowp(s)?0:strtol(s,e,b); }
static unsigned long __attribute__((sysv_abi)) _s_strtoul(const char *s,char **e,int b){ return _lowp(s)?0:strtoul(s,e,b); }
static long long __attribute__((sysv_abi)) _s_strtoll(const char *s,char **e,int b){ return _lowp(s)?0:strtoll(s,e,b); }
static unsigned long long __attribute__((sysv_abi)) _s_strtoull(const char *s,char **e,int b){ return _lowp(s)?0:strtoull(s,e,b); }
static double __attribute__((sysv_abi)) _s_strtod(const char *s,char **e){ return _lowp(s)?0:strtod(s,e); }
static float  __attribute__((sysv_abi)) _s_strtof(const char *s,char **e){ return _lowp(s)?0:strtof(s,e); }
static int    __attribute__((sysv_abi)) _s_atoi(const char *s){ return _lowp(s)?0:atoi(s); }
static long   __attribute__((sysv_abi)) _s_atol(const char *s){ return _lowp(s)?0:atol(s); }
static long long __attribute__((sysv_abi)) _s_atoll(const char *s){ return _lowp(s)?0:atoll(s); }
static double __attribute__((sysv_abi)) _s_atof(const char *s){ return _lowp(s)?0:atof(s); }

/* ── stdio: variadic output suppressed (Android init passes bad %s args);
 *    snprintf/vsnprintf still format (they build strings), file ops pass
 *    through. All sysv_abi. ─────────────────────────────────────────────── */
static int __attribute__((sysv_abi)) _v_noprint(const char *fmt,...){(void)fmt;return 0;}
static int __attribute__((sysv_abi)) _v_fnoprint(void *f,const char *fmt,...){(void)f;(void)fmt;return 0;}
static int __attribute__((sysv_abi)) _sysv_snprintf(char *b,size_t n,const char *fmt,...){ va_list ap; va_start(ap,fmt); int r=vsnprintf(b,n,fmt,ap); va_end(ap); return r; }
static int __attribute__((sysv_abi)) _sysv_vsnprintf(char *b,size_t n,const char *fmt,va_list ap){ return vsnprintf(b,n,fmt,ap); }
static void *__attribute__((sysv_abi)) _sysv_fopen(const char *p,const char *m){ return (_lowp(p)||_lowp(m))?NULL:(void*)fopen(p,m); }
static int  __attribute__((sysv_abi)) _sysv_fclose(void *f){ return f?fclose((FILE*)f):0; }
static size_t __attribute__((sysv_abi)) _sysv_fread(void *b,size_t s,size_t n,void *f){ return f?fread(b,s,n,(FILE*)f):0; }
static size_t __attribute__((sysv_abi)) _sysv_fwrite(const void *b,size_t s,size_t n,void *f){ return f?fwrite(b,s,n,(FILE*)f):0; }

/* ── process / misc (sysv_abi) ──────────────────────────────────────────── */
static void __attribute__((sysv_abi)) _sysv_abort(void){ abort(); }
static void __attribute__((sysv_abi)) _sysv_exit(int c){ exit(c); }
static char *__attribute__((sysv_abi)) _sysv_getenv(const char *n){ return _lowp(n)?NULL:getenv(n); }
static void __attribute__((sysv_abi)) _sysv_qsort(void *base,size_t n,size_t sz,int(__attribute__((sysv_abi))*cmp)(const void*,const void*))
{ /* wrap the SysV comparator for the host qsort via a thread-local shim */
  /* Simpler: insertion-sort-free — delegate to host qsort using a static cmp. */
  /* To keep the comparator ABI correct, use a small bubble over the SysV cmp. */
  char *a=(char*)base; char tmp[512];
  if (sz>sizeof(tmp)) { qsort(base,n,sz,(int(*)(const void*,const void*))cmp); return; }
  for (size_t i=0;i<n;i++) for (size_t j=i+1;j<n;j++)
    if (cmp(a+i*sz,a+j*sz)>0){ memcpy(tmp,a+i*sz,sz); memcpy(a+i*sz,a+j*sz,sz); memcpy(a+j*sz,tmp,sz); }
}
static long __attribute__((sysv_abi)) _sysv_time(long *t){ time_t r=time(NULL); if(t)*t=(long)r; return (long)r; }

/* Bionic implements these via a raw `syscall` instruction. Executed on Windows
 * that traps into the Windows kernel with a Linux syscall number (and the
 * `syscall` instruction clobbers rcx/r11), corrupting the guest. libc++'s
 * __cxa_guard_release does syscall(SYS_futex, FUTEX_WAKE) on every static-init
 * guard, which crashed locale initialization. Provide Windows-safe stand-ins.
 * Fixed 6-arg prototype: SysV passes the first 6 args in registers, so this
 * reads them correctly no matter how many the caller actually supplied. */
static long __attribute__((sysv_abi)) _sysv_sched_yield(void){
    static volatile long yc=0; long c=++yc;
    if ((c%200000)==1) fprintf(stderr,"[sched_yield] call #%ld ra=%p\n", c, __builtin_return_address(0));
    SwitchToThread(); return 0;
}
static long __attribute__((sysv_abi)) _sysv_nanosleep(const long *req, long *rem){
  (void)rem;
  if (req){ long long ms = (long long)req[0]*1000 + req[1]/1000000;
            static volatile long nc=0; long c=++nc;
            if ((c%200000)==1) fprintf(stderr,"[nanosleep] #%ld sec=%lld nsec=%lld ms=%lld ra=%p\n",
                                       c,(long long)req[0],(long long)req[1],ms,__builtin_return_address(0));
            if (ms < 0) ms = 0; if (ms == 0 && (req[0]||req[1])) ms = 1; Sleep((DWORD)ms); }
  return 0;
}
/* bionic clock_gettime/clock_getres are syscall-based too. libCoreFoundation
 * does CHECK(clock_getres(CLOCK_MONOTONIC, &res) == 0) and ud2's on failure.
 * Write the timespec as two explicit 8-byte fields: bionic's tv_nsec is 64-bit
 * (LP64), but MinGW's `long` is 32-bit (LLP64), so struct timespec differs. */
static long __attribute__((sysv_abi)) _sysv_clock_gettime(int clk, long long *tp){
  if (!tp) { errno = 14 /*EFAULT*/; return -1; }
  if (clk == 0 /*CLOCK_REALTIME*/) {
    FILETIME ft; GetSystemTimePreciseAsFileTime(&ft);
    unsigned long long t = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    t -= 116444736000000000ULL;  /* 1601 -> 1970 in 100ns units */
    tp[0] = (long long)(t / 10000000ULL);
    tp[1] = (long long)((t % 10000000ULL) * 100);
  } else {  /* MONOTONIC and friends */
    LARGE_INTEGER c, f; QueryPerformanceCounter(&c); QueryPerformanceFrequency(&f);
    if (f.QuadPart == 0) { tp[0] = 0; tp[1] = 0; return 0; }
    tp[0] = (long long)(c.QuadPart / f.QuadPart);
    tp[1] = (long long)(((c.QuadPart % f.QuadPart) * 1000000000ULL) / f.QuadPart);
  }
  return 0;
}
static long __attribute__((sysv_abi)) _sysv_clock_getres(int clk, long long *res){
  (void)clk;
  if (res) { res[0] = 0; res[1] = 1; }  /* 1 ns */
  return 0;
}
static long __attribute__((sysv_abi)) _sysv_syscall(long n, long a1, long a2, long a3, long a4, long a5){
  (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
  switch (n) {
    case 24:  { static volatile long yc=0; long c=++yc; if((c%200000)==1) fprintf(stderr,"[syscall sched_yield] #%ld ra=%p\n",c,__builtin_return_address(0)); SwitchToThread(); return 0; }  /* __NR_sched_yield */
    case 35:  return _sysv_nanosleep((const long*)a1,(long*)a2); /* __NR_nanosleep */
    case 39:  return (long)GetCurrentProcessId();          /* __NR_getpid */
    case 186: return (long)GetCurrentThreadId();           /* __NR_gettid */
    case 202: { static volatile long fc=0; long c=++fc; if(c<=60 && (a2&0x7f)!=1) WTRACE("[wtrace] futex #%ld tid=%lu op=%ld uaddr=%p val=%ld\n",c,GetCurrentThreadId(),a2,(void*)a1,a3); if((c%200000)==1) fprintf(stderr,"[futex] call #%ld op=%ld uaddr=%p\n",c,a2,(void*)a1); return 0; }  /* __NR_futex: diagnostic spin counter */
    case 234: return 0;                                    /* __NR_tgkill */
    default:  { static volatile long uc=0; long c=++uc; if(c<=80) { fprintf(stderr,"[guest-libc] UNHANDLED syscall n=%ld tid=%lu ra=%p (failing with ENOSYS)\n",n,GetCurrentThreadId(),__builtin_return_address(0)); fflush(stderr);} } errno = 38 /*ENOSYS*/; return -1;
  }
}
static int *__attribute__((sysv_abi)) _win32_errno_location(void){ return _errno(); }

/* ── POSIX file I/O: bionic's open/read/close/lseek are raw Linux syscalls that
 * fail on Windows. Route them through the host CRT, and synthesize /dev/urandom
 * and /dev/random from the Windows system RNG (std::random_device needs it). ── */
extern unsigned char __stdcall SystemFunction036(void *buf, unsigned long len); /* RtlGenRandom, advapi32 */
static int   g_ur[64];
static volatile long g_urn = 0;
static int _is_ur(int fd){ for (long i=0;i<g_urn;i++) if (g_ur[i]==fd) return 1; return 0; }
/* libmediaplatform hands its SQLite/FairPlay paths to us as POSIX-absolute
 * "/C:/Users/..." (see drm_posix_path in drm/native/main.c): the leading '/'
 * keeps the bionic unix VFS on its absolute branch. Strip that one slash so the
 * real Win32 call sees "C:/Users/...". Only a genuine drive-letter path
 * ("/<L>:...") is touched; real bionic paths (/dev, /proc, /data) are left
 * alone, since none has ':' at index 2. */
static const char *_winpath(const char *p){
    if (p && p[0]=='/' && ((p[1]>='A'&&p[1]<='Z')||(p[1]>='a'&&p[1]<='z')) && p[2]==':')
        return p + 1;
    return p;
}

/* SQLite opens the database directory so it can fsync the directory after a
 * journal/WAL update. The Windows CRT cannot open directories, so represent
 * directory-only handles synthetically and handle them explicitly below. */
#define DIRFD_BASE 0x30000000
#define DIRFD_MAX  128
static volatile LONG g_dirfd_used[DIRFD_MAX];
static int _dirfd_alloc(void){
    for (int i=0; i<DIRFD_MAX; ++i)
        if (InterlockedCompareExchange(&g_dirfd_used[i], 1, 0) == 0)
            return DIRFD_BASE + i;
    errno = EMFILE;
    return -1;
}
static int _dirfd_is(int fd){
    return fd >= DIRFD_BASE && fd < DIRFD_BASE + DIRFD_MAX &&
           g_dirfd_used[fd - DIRFD_BASE] != 0;
}
static int _dirfd_close(int fd){
    if (!_dirfd_is(fd)){ errno = EBADF; return -1; }
    InterlockedExchange(&g_dirfd_used[fd - DIRFD_BASE], 0);
    return 0;
}

/* UCRT may report st_ino==0 for Windows files. SQLite combines st_dev and
 * st_ino to identify each database's WAL shared-memory node; a common fallback
 * inode aliases all databases to the first -shm mapping. Keep a stable inode
 * derived from the canonical path and remember it for fstat(fd). */
static unsigned long long _path_ino(const char *p){
    const unsigned char *s = (const unsigned char *)(p ? p : "");
    unsigned long long h = 1469598103934665603ULL;
    while (*s){ h ^= (unsigned long long)*s++; h *= 1099511628211ULL; }
    return h ? h : 1ULL;
}
static unsigned long long g_fd_ino[4096];
static void _remember_fd_ino(int fd, const char *p){
    if (fd >= 0 && fd < (int)(sizeof g_fd_ino / sizeof g_fd_ino[0]))
        g_fd_ino[fd] = _path_ino(p);
}
static unsigned long long _fd_ino(int fd){
    return (fd >= 0 && fd < (int)(sizeof g_fd_ino / sizeof g_fd_ino[0]))
        ? g_fd_ino[fd] : 0;
}
/* Env-gated (ADAM_DB_DEBUG) tracing of the SQLite/file-op layer. */
static int _dbg(void){ static int v=-1; if(v<0){ char b[8]; DWORD n=GetEnvironmentVariableA("ADAM_DB_DEBUG",b,sizeof b); v=(n>0 && n<sizeof b && b[0] && b[0]!='0')?1:0; } return v; }
/* Write via the raw Win32 stderr handle, bypassing q.so's CRT stdio (whose
 * FILE* may not be wired to the inherited/redirected OS handle). */
static void _dbgw(const char *fmt, ...){
    if(!_dbg()) return;
    char b[512]; int p=0;
    b[p++]='['; b[p++]='d'; b[p++]='b'; b[p++]='g'; b[p++]=']'; b[p++]=' ';
    va_list ap; va_start(ap,fmt);
    int n=vsnprintf(b+p,sizeof(b)-p,fmt,ap); va_end(ap);
    if(n>0){ DWORD wr; WriteFile(GetStdHandle(STD_ERROR_HANDLE), b, (DWORD)(p+n), &wr, NULL); }
}
#define DBG(...) _dbgw(__VA_ARGS__)
static int __attribute__((sysv_abi)) _sysv_open(const char *path, int bflags, int mode){
    if ((uintptr_t)path < 0x10000u) return -1;
    if (!strcmp(path,"/dev/urandom") || !strcmp(path,"/dev/random")){
        int fd = _open("NUL", _O_RDONLY | _O_BINARY);
        if (fd >= 0){ long i = g_urn; if (i < 64){ g_ur[i] = fd; g_urn = i + 1; } }
        return fd;
    }
    int wf = (bflags & 3);        /* O_RDONLY/WRONLY/RDWR = 0/1/2 on both */
    if (bflags & 0100)  wf |= _O_CREAT;   /* O_CREAT  */
    if (bflags & 01000) wf |= _O_TRUNC;   /* O_TRUNC  */
    if (bflags & 0200)  wf |= _O_EXCL;    /* O_EXCL   */
    if (bflags & 02000) wf |= _O_APPEND;  /* O_APPEND */
    wf |= _O_BINARY;
    const char *wp = _winpath(path);
    struct _stat64 pst;
    if (_stat64(wp, &pst) == 0 && (pst.st_mode & _S_IFMT) == _S_IFDIR){
        int dfd = _dirfd_alloc();
        DBG("open directory(\"%s\") -> dfd=%d errno=%d\n", path, dfd, dfd < 0 ? errno : 0);
        return dfd;
    }
    int rfd = _open(wp, wf, mode ? mode : 0666);
    if (rfd >= 0) _remember_fd_ino(rfd, wp);
    DBG("open(\"%s\" bflags=0%o) -> fd=%d errno=%d\n", path, bflags, rfd, rfd<0?errno:0);
    return rfd;
}
static int __attribute__((sysv_abi)) _sysv_openat(int dirfd, const char *path, int bflags, int mode){
    (void)dirfd;  /* AT_FDCWD only; the guest uses absolute/base-relative paths */
    return _sysv_open(path, bflags, mode);
}
/* bionic _FORTIFY_SOURCE open: int __open_2(const char*, int). libc++'s
 * random_device uses this, not open(). */
static int __attribute__((sysv_abi)) _sysv_open_2(const char *path, int bflags){
    return _sysv_open(path, bflags, 0);
}
static long __attribute__((sysv_abi)) _sysv_read(int fd, void *buf, size_t n){
    if (_dirfd_is(fd)){ errno = EBADF; return -1; }
    if (_net_is_fd(fd)) return _net_read(fd, buf, n);
    if (_is_ur(fd)){ if (!SystemFunction036(buf,(unsigned long)n)) return -1; return (long)n; }
    long r=_read(fd, buf, (unsigned)n); DBG("read(fd=%d n=%zu) -> %ld\n", fd, n, r); return r;
}
static long __attribute__((sysv_abi)) _sysv_write(int fd, const void *buf, size_t n){
    if (_dirfd_is(fd)){ errno = EBADF; return -1; }
    if (_net_is_fd(fd)) return _net_write(fd, buf, n);
    return _write(fd, buf, (unsigned)n); }
static int __attribute__((sysv_abi)) _sysv_close(int fd){
    if (_dirfd_is(fd)) return _dirfd_close(fd);
    if (_net_is_fd(fd)) return _net_close(fd);
    for (long i=0;i<g_urn;i++) if (g_ur[i]==fd){ g_ur[i]=g_ur[--g_urn]; break; }
    return _close(fd);
}
static long long __attribute__((sysv_abi)) _sysv_lseek(int fd, long long off, int whence){
    if (_dirfd_is(fd)){ errno = ESPIPE; return -1; }
    if (_is_ur(fd)) return 0;
    long long r=_lseeki64(fd, off, whence); DBG("lseek(fd=%d off=%lld whence=%d) -> %lld\n", fd, off, whence, r); return r;
}
/* SQLite's unix VFS needs more file ops. Fill bionic's x86-64 struct stat layout
 * (st_dev@0, st_ino@8, st_nlink@16, st_mode@24, st_rdev@40, st_size@48,
 * st_blksize@56, st_blocks@64, st_atim@72, st_mtim@88, st_ctim@104; 144 bytes). */
static void _fill_bionic_stat(void *bst, const struct _stat64 *w){
    unsigned char *p = (unsigned char*)bst; memset(p, 0, 144);
    *(unsigned long long*)(p+0)  = (unsigned long long)w->st_dev;
    *(unsigned long long*)(p+8)  = w->st_ino ? (unsigned long long)w->st_ino : 1ULL;
    *(unsigned long long*)(p+16) = w->st_nlink ? (unsigned long long)w->st_nlink : 1ULL;
    *(unsigned int*)(p+24)       = (unsigned int)w->st_mode;
    *(unsigned long long*)(p+40) = (unsigned long long)w->st_rdev;
    *(long long*)(p+48)          = (long long)w->st_size;
    *(long long*)(p+56)          = 4096;
    *(long long*)(p+64)          = ((long long)w->st_size + 511) / 512;
    *(long long*)(p+72)          = (long long)w->st_atime;
    *(long long*)(p+88)          = (long long)w->st_mtime;
    *(long long*)(p+104)         = (long long)w->st_ctime;
}
static int __attribute__((sysv_abi)) _sysv_fstat(int fd, void *bst){
    if (_dirfd_is(fd)){
        struct _stat64 w; memset(&w, 0, sizeof w);
        w.st_mode = _S_IFDIR | _S_IREAD | _S_IWRITE;
        _fill_bionic_stat(bst, &w);
        return 0;
    }
    struct _stat64 w; if (_fstat64(fd, &w) != 0) return -1;
    _fill_bionic_stat(bst, &w);
    unsigned long long ino = _fd_ino(fd);
    if (ino) *(unsigned long long *)((unsigned char *)bst + 8) = ino;
    return 0;
}
static int __attribute__((sysv_abi)) _sysv_stat(const char *path, void *bst){
    if ((uintptr_t)path < 0x10000u) return -1;
    const char *wp = _winpath(path);
    struct _stat64 w; int rc=_stat64(wp, &w); DBG("stat(\"%s\") -> %d errno=%d size=%lld\n", path, rc, rc?errno:0, rc?0:(long long)w.st_size); if (rc != 0) return -1; _fill_bionic_stat(bst, &w); *(unsigned long long *)((unsigned char *)bst + 8) = _path_ino(wp); return 0;
}
/* Windows has no POSIX symlinks here, so lstat == stat. SQLite's
 * unixFullPathname resolves symlinks with lstat/readlink; left unhooked these
 * fall through to bionic's raw Linux syscalls and return garbage, making path
 * resolution fail nondeterministically (SQLITE_CANTOPEN). */
static int __attribute__((sysv_abi)) _sysv_lstat(const char *path, void *bst){
    return _sysv_stat(path, bst);
}
/* readlink: resolve /proc/self/exe to the real executable path (bionic code
 * uses it to locate the app); for any other path report "not a symlink"
 * (EINVAL) so SQLite's unixFullPathname stops resolving and uses it as-is. */
static long __attribute__((sysv_abi)) _sysv_readlink(const char *path, char *buf, size_t sz){
    if (path && !strcmp(path, "/proc/self/exe")){
        DWORD n = GetModuleFileNameA(NULL, buf, (DWORD)sz);
        DBG("readlink(\"/proc/self/exe\") -> %lu\n", (unsigned long)n);
        return (n == 0 || n >= sz) ? -1 : (long)n;
    }
    errno = EINVAL; DBG("readlink(\"%s\") -> -1 (EINVAL)\n", path?path:"(null)"); return -1;
}
static long __attribute__((sysv_abi)) _sysv_pread64(int fd, void *buf, size_t n, long long off){
    if (_is_ur(fd)){ if (!SystemFunction036(buf,(unsigned long)n)) return -1; return (long)n; }
    HANDLE h = (HANDLE)(intptr_t)_get_osfhandle(fd); if (h==INVALID_HANDLE_VALUE) return -1;
    OVERLAPPED ov; memset(&ov,0,sizeof ov); ov.Offset=(DWORD)off; ov.OffsetHigh=(DWORD)(off>>32);
    DWORD got=0; if (!ReadFile(h, buf, (DWORD)n, &got, &ov)){ if (GetLastError()==ERROR_HANDLE_EOF){ DBG("pread64(fd=%d n=%zu off=%lld) -> 0 (EOF)\n",fd,n,off); return 0;} DBG("pread64(fd=%d n=%zu off=%lld) -> -1 gle=%lu\n",fd,n,off,GetLastError()); return -1; }
    DBG("pread64(fd=%d n=%zu off=%lld) -> %lu\n",fd,n,off,got); return (long)got;
}
static long __attribute__((sysv_abi)) _sysv_pwrite64(int fd, const void *buf, size_t n, long long off){
    HANDLE h = (HANDLE)(intptr_t)_get_osfhandle(fd); if (h==INVALID_HANDLE_VALUE) return -1;
    OVERLAPPED ov; memset(&ov,0,sizeof ov); ov.Offset=(DWORD)off; ov.OffsetHigh=(DWORD)(off>>32);
    DWORD put=0; if (!WriteFile(h, buf, (DWORD)n, &put, &ov)){ DBG("pwrite64(fd=%d n=%zu off=%lld) -> -1 gle=%lu\n",fd,n,off,GetLastError()); return -1; } DBG("pwrite64(fd=%d n=%zu off=%lld) -> %lu\n",fd,n,off,put); return (long)put;
}
/* fcntl: single-process, so advisory locks always succeed; F_GETLK(5) reports no
 * conflicting lock (l_type = F_UNLCK = 2 at offset 0 of struct flock). */
static int __attribute__((sysv_abi)) _sysv_fcntl(int fd, int cmd, void *arg){
    if (_dirfd_is(fd)) return 0;
    if (_net_is_fd(fd)){ int r=_net_fcntl(fd, cmd, (int)(intptr_t)arg); if (r != -2) return r; }
    DBG("fcntl(fd=%d cmd=%d)\n", fd, cmd);
    if (cmd == 5 && arg) *(short*)arg = 2;
    return 0;
}
static int __attribute__((sysv_abi)) _sysv_access(const char *p, int m){ if((uintptr_t)p<0x10000u) return -1; int r=_access(_winpath(p), m & 06); DBG("access(\"%s\" m=%d) -> %d errno=%d\n", p, m, r, r?errno:0); return r; }
static int __attribute__((sysv_abi)) _sysv_fsync(int fd){
    if (_dirfd_is(fd)){ DBG("fsync(directory fd=%d) -> 0\n", fd); return 0; }
    errno = 0; int rc = _commit(fd);
    DBG("fsync(fd=%d) -> %d errno=%d\n", fd, rc, rc ? errno : 0);
    return rc;
}
static int __attribute__((sysv_abi)) _sysv_ftruncate(int fd, long long len){
    if (_dirfd_is(fd)){ errno = EINVAL; return -1; }
    errno = 0; errno_t rc = _chsize_s(fd, (__int64)len);
    DBG("ftruncate(fd=%d len=%lld) -> %d errno=%d\n", fd, len, (int)rc, rc ? errno : 0);
    return rc == 0 ? 0 : -1;
}
static char *__attribute__((sysv_abi)) _sysv_getcwd(char *buf, size_t size){ return _getcwd(buf, (int)size); }
static int __attribute__((sysv_abi)) _sysv_mkdir(const char *p, int mode){ (void)mode; if((uintptr_t)p<0x10000u) return -1; return _mkdir(_winpath(p)); }
static int __attribute__((sysv_abi)) _sysv_unlink(const char *p){ if((uintptr_t)p<0x10000u) return -1; return _unlink(_winpath(p)); }
static int __attribute__((sysv_abi)) _sysv_fchmod(int fd,int m){(void)fd;(void)m;return 0;}
static int __attribute__((sysv_abi)) _sysv_fchown(int fd,int u,int g){(void)fd;(void)u;(void)g;return 0;}

/* ── mmap family (guest -> VirtualAlloc, sysv_abi) ──────────────────────── */
static DWORD _mprot(int prot){ if(prot==0)return PAGE_NOACCESS; if(prot&4)return (prot&2)?PAGE_EXECUTE_READWRITE:PAGE_EXECUTE_READ; if(prot&2)return PAGE_READWRITE; if(prot&1)return PAGE_READONLY; return PAGE_NOACCESS; }
static void *__attribute__((sysv_abi)) _sysv_mmap(void *addr,size_t len,int prot,int flags,int fd,long long off)
{ if(len==0)return (void*)-1;
  /* File-backed mmap (fd>=0, not MAP_ANONYMOUS=0x20): map the real file through
     a Windows section. SQLite's WAL uses a MAP_SHARED mapping of the "-shm"
     wal-index file and cannot proceed if it fails. CreateFileMapping with
     max-size 0 covers the current file size (SQLite ftruncates the -shm first);
     the view stays valid after the mapping handle is closed. off must be
     allocation-granularity aligned, which SQLite's offset 0 satisfies. */
  if(fd>=0 && !(flags&0x20)){
    HANDLE fh=(HANDLE)(intptr_t)_get_osfhandle(fd);
    if(fh==INVALID_HANDLE_VALUE){ DBG("mmap fd=%d bad handle\n",fd); return (void*)-1; }
    DWORD pm=(prot&2)?PAGE_READWRITE:PAGE_READONLY;
    DWORD acc=(prot&2)?FILE_MAP_WRITE:FILE_MAP_READ;
    HANDLE hm=CreateFileMappingA(fh,NULL,pm,0,0,NULL);
    if(!hm){ DBG("mmap CreateFileMapping fd=%d gle=%lu\n",fd,GetLastError()); return (void*)-1; }
    void *v=MapViewOfFile(hm,acc,(DWORD)(off>>32),(DWORD)off,len);
    CloseHandle(hm);
    if(!v){ DBG("mmap MapViewOfFile fd=%d len=%zu off=%lld gle=%lu\n",fd,len,off,GetLastError()); return (void*)-1; }
    DBG("mmap file fd=%d len=%zu off=%lld -> %p\n",fd,len,off,v);
    return v;
  }
  (void)off;
  if(prot==0){ void*r=VirtualAlloc(addr,len,MEM_RESERVE,PAGE_NOACCESS); if(!r&&addr)r=VirtualAlloc(NULL,len,MEM_RESERVE,PAGE_NOACCESS); return r?r:(void*)-1; }
  DWORD wp=_mprot(prot); void*r; if(flags&0x10){ r=VirtualAlloc(addr,len,MEM_COMMIT,wp); if(r)return r; }
  r=VirtualAlloc(addr,len,MEM_RESERVE|MEM_COMMIT,wp); if(!r)r=VirtualAlloc(NULL,len,MEM_RESERVE|MEM_COMMIT,wp); return r?r:(void*)-1; }
static int __attribute__((sysv_abi)) _sysv_munmap(void *addr,size_t len){
  /* A file-backed mapping (from _sysv_mmap) must be released with
     UnmapViewOfFile; it fails harmlessly on a VirtualAlloc'd region, so try it
     first, then fall back to the anonymous-memory path. */
  if(UnmapViewOfFile(addr))return 0;
  if(VirtualFree(addr,len,MEM_DECOMMIT))return 0; return VirtualFree(addr,0,MEM_RELEASE)?0:-1; }
static int __attribute__((sysv_abi)) _sysv_mprotect(void *addr,size_t len,int prot){ DWORD old; DWORD wp=_mprot(prot); MEMORY_BASIC_INFORMATION mbi;
  if(VirtualQuery(addr,&mbi,sizeof(mbi))&&mbi.State==MEM_RESERVE)return VirtualAlloc(addr,len,MEM_COMMIT,wp)?0:-1; return VirtualProtect(addr,len,wp,&old)?0:-1; }

/* ── dl* (guest SysV -> Windows-ABI android_*) ──────────────────────────── */
static void *__attribute__((sysv_abi)) _sysv_dlopen(const char *f,int fl){return android_dlopen(f,fl);}
static void *__attribute__((sysv_abi)) _sysv_dlsym(void *h,const char *s){return android_dlsym(h,s);}
static int   __attribute__((sysv_abi)) _sysv_dlclose(void *h){return android_dlclose(h);}
static char *__attribute__((sysv_abi)) _sysv_dlerror(void){return android_dlerror();}
static int   __attribute__((sysv_abi)) _sysv_dladdr(const void *a,void *i){return android_dladdr(a,i);}
static int   __attribute__((sysv_abi)) _sysv_dl_iterate_phdr(void *cb,void *d){return android_dl_iterate_phdr((int(*)(void*,size_t,void*))cb,d);}

/* ── Android log (liblog.so) — sysv_abi, suppressed ─────────────────────── */
static void _alog_emit(const char *tag,const char *msg){
    if(!_dbg()) return; char b[1024];
    int n=snprintf(b,sizeof b,"[alog] %s: %s\n", tag?tag:"", msg?msg:"");
    if(n>0){ if(n>(int)sizeof b)n=sizeof b; DWORD wr; WriteFile(GetStdHandle(STD_ERROR_HANDLE),b,(DWORD)n,&wr,NULL); }
}
static int __attribute__((sysv_abi)) _win32_android_log_print(int prio,const char *tag,const char *fmt,...){
    /* Variadic + sysv_abi va handling is unsafe from this Windows-ABI build, so
     * emit the (unexpanded) format string rather than running va_start. */
    (void)prio; _alog_emit(tag,fmt); return 0; }
/* __android_log_write(prio, tag, text): text is a literal message, not a fmt. */
static int __attribute__((sysv_abi)) _win32_android_log_write(int prio,const char *tag,const char *text){
    (void)prio; _alog_emit(tag,text); return 0; }
static int __attribute__((sysv_abi)) _win32_android_log_buf_print(int buf,int prio,const char *tag,const char *fmt,...){(void)buf;(void)prio;(void)tag;(void)fmt;return 0;}
static int __attribute__((sysv_abi)) _win32___android_log_is_loggable(int p,const char *t,int d){(void)p;(void)t;(void)d;return 1;}

struct _w32_hook { const char *name; void *fn; };
#define H(sym)        { #sym,  (void *)(sym) }          /* raw host (FP-only math) */
#define HW(sym)       { #sym,  (void *)(_hybris_win32_##sym) }
#define HA(sym, fn)   { #sym,  (void *)(fn) }

/* Windows implementations (or loud failures) for libc functions that would otherwise
 * fall through to the guest's raw-syscall libc.so; see the header for the policy. */
#include "windows_libc_shims.h"

static const struct _w32_hook win32_hooks[] = {
    /* dl* */
    HA(dlopen,_sysv_dlopen), HA(dlsym,_sysv_dlsym), HA(dlclose,_sysv_dlclose),
    HA(dlerror,_sysv_dlerror), HA(dladdr,_sysv_dladdr), HA(dl_iterate_phdr,_sysv_dl_iterate_phdr),

    /* pthread lifecycle */
    HW(pthread_atfork),
    HA(pthread_create,_bionic_pthread_create),
    HA(pthread_kill,_bionic_pthread_kill),
    HA(pthread_sigmask,_bionic_pthread_sigmask),
    HW(pthread_exit), HW(pthread_join), HW(pthread_detach), HW(pthread_self),
    HW(pthread_equal), HW(pthread_getschedparam), HW(pthread_setschedparam),

    /* pthread mutex (bionic int32 spinlock) */
    HA(pthread_mutex_init,_bionic_mutex_init), HA(pthread_mutex_destroy,_bionic_mutex_destroy),
    HA(pthread_mutex_lock,_bionic_mutex_lock), HA(pthread_mutex_unlock,_bionic_mutex_unlock),
    HA(pthread_mutex_trylock,_bionic_mutex_trylock), HA(pthread_mutex_timedlock,_bionic_mutex_timedlock),
    HW(pthread_mutexattr_init), HW(pthread_mutexattr_destroy), HW(pthread_mutexattr_gettype),
    HW(pthread_mutexattr_settype), HW(pthread_mutexattr_getpshared), HW(pthread_mutexattr_setpshared),
    HW(pthread_mutexattr_getprotocol), HW(pthread_mutexattr_setprotocol),

    /* pthread cond (bionic) */
    HA(pthread_cond_init,_bionic_cond_init), HA(pthread_cond_destroy,_bionic_cond_destroy),
    HA(pthread_cond_broadcast,_bionic_cond_broadcast), HA(pthread_cond_signal,_bionic_cond_signal),
    HA(pthread_cond_wait,_bionic_cond_wait), HA(pthread_cond_timedwait,_bionic_cond_timedwait),
    HW(pthread_condattr_init), HW(pthread_condattr_destroy), HW(pthread_condattr_getpshared),
    HW(pthread_condattr_setpshared), HW(pthread_condattr_getclock), HW(pthread_condattr_setclock),

    /* pthread key / once / attr */
    HW(pthread_key_create), HW(pthread_key_delete), HA(pthread_getspecific,_bionic_getspecific),
    HW(pthread_setspecific), HA(pthread_once,_bionic_pthread_once), HW(pthread_getname_np),
    HA(pthread_attr_init,_bionic_attr_init), HA(pthread_attr_destroy,_bionic_attr_destroy),
    HA(pthread_attr_setdetachstate,_bionic_attr_setdetachstate), HA(pthread_attr_getdetachstate,_bionic_attr_getdetachstate),
    HA(pthread_attr_setschedpolicy,_bionic_attr_setschedpolicy), HA(pthread_attr_getschedpolicy,_bionic_attr_getschedpolicy),
    HA(pthread_attr_setschedparam,_bionic_attr_setschedparam), HA(pthread_attr_getschedparam,_bionic_attr_getschedparam),
    HA(pthread_attr_setstacksize,_bionic_attr_setstacksize), HA(pthread_attr_getstacksize,_bionic_attr_getstacksize),

    /* pthread rwlock (bionic) */
    HA(pthread_rwlock_init,_bionic_rwlock_init), HA(pthread_rwlock_destroy,_bionic_rwlock_destroy),
    HA(pthread_rwlock_rdlock,_bionic_rwlock_rdlock), HA(pthread_rwlock_wrlock,_bionic_rwlock_wrlock),
    HA(pthread_rwlock_unlock,_bionic_rwlock_unlock), HA(pthread_rwlock_tryrdlock,_bionic_rwlock_tryrdlock),
    HA(pthread_rwlock_trywrlock,_bionic_rwlock_trywrlock),

    /* memory mapping */
    HA(mmap,_sysv_mmap), HA(munmap,_sysv_munmap), HA(mprotect,_sysv_mprotect),

    /* allocator */
    HA(malloc,_sysv_malloc), HA(free,_sysv_free), HA(calloc,_sysv_calloc), HA(realloc,_sysv_realloc),
    HA(malloc_usable_size,_sysv_malloc_usable_size), HA(memalign,_sysv_memalign),
    HA(posix_memalign,_sysv_posix_memalign), HA(aligned_alloc,_sysv_aligned_alloc),

    /* mem family */
    HA(memcpy,_sysv_memcpy), HA(memmove,_sysv_memmove), HA(memset,_sysv_memset),
    HA(memcmp,_sysv_memcmp), HA(memchr,_sysv_memchr),

    /* string */
    HA(strcmp,_s_strcmp), HA(strncmp,_s_strncmp), HA(strcasecmp,_s_strcasecmp), HA(strncasecmp,_s_strncasecmp),
    HA(strcpy,_s_strcpy), HA(strncpy,_s_strncpy), HA(strcat,_s_strcat), HA(strncat,_s_strncat),
    HA(strlen,_s_strlen), HA(strchr,_s_strchr), HA(strrchr,_s_strrchr), HA(strstr,_s_strstr), HA(strdup,_s_strdup),
    HA(strtol,_s_strtol), HA(strtoul,_s_strtoul), HA(strtoll,_s_strtoll), HA(strtoull,_s_strtoull),
    HA(strtod,_s_strtod), HA(strtof,_s_strtof), HA(atoi,_s_atoi), HA(atol,_s_atol), HA(atoll,_s_atoll), HA(atof,_s_atof),

    /* stdio */
    HA(printf,_v_noprint), HA(vprintf,(void*)_v_noprint),
    HA(fprintf,_v_fnoprint), HA(vfprintf,(void*)_v_fnoprint),
    /* sprintf/snprintf/vsprintf/vsnprintf: see win32_shim_hooks (SysV va_list aware) */
    HA(fopen,_sysv_fopen), HA(fclose,_sysv_fclose), HA(fread,_sysv_fread), HA(fwrite,_sysv_fwrite),

    /* process / misc */
    HA(abort,_sysv_abort), HA(exit,_sysv_exit), HA(getenv,_sysv_getenv),
    HA(qsort,_sysv_qsort), HA(time,_sysv_time),
    /* syscall-based bionic functions: replace the raw `syscall` instruction
     * (invalid on Windows) with Windows-safe stand-ins. */
    HA(syscall,_sysv_syscall), HA(sched_yield,_sysv_sched_yield),
    HA(nanosleep,_sysv_nanosleep),
    HA(clock_gettime,_sysv_clock_gettime), HA(clock_getres,_sysv_clock_getres),
    /* bionic libc exports the errno accessor as __errno (glibc uses
     * __errno_location); hook both so bionic code such as
     * __system_properties_init does not fall through to bionic's own __errno,
     * which reads an uninitialised thread pointer and returns a bogus pointer. */
    HA(__errno,_win32_errno_location),
    HA(__errno_location,_win32_errno_location),
    /* POSIX file I/O via the host CRT; /dev/urandom from the Windows RNG. */
    HA(open,_sysv_open), HA(open64,_sysv_open), HA(openat,_sysv_openat),
    HA(__open_2,_sysv_open_2),
    HA(read,_sysv_read), HA(write,_sysv_write), HA(close,_sysv_close),
    HA(lseek,_sysv_lseek), HA(lseek64,_sysv_lseek),
    HA(fstat,_sysv_fstat), HA(stat,_sysv_stat), HA(lstat,_sysv_lstat), HA(readlink,_sysv_readlink),
    HA(pread64,_sysv_pread64), HA(pwrite64,_sysv_pwrite64),
    HA(fcntl,_sysv_fcntl), HA(access,_sysv_access),
    HA(fsync,_sysv_fsync), HA(fdatasync,_sysv_fsync), HA(ftruncate,_sysv_ftruncate),
    HA(getcwd,_sysv_getcwd), HA(mkdir,_sysv_mkdir), HA(unlink,_sysv_unlink),
    HA(fchmod,_sysv_fchmod), HA(fchown,_sysv_fchown),

    /* Winsock shim (hybris_net.c): Apple's networking (libcurl/libssl) over
     * Windows sockets, with bionic<->Windows translation. */
    HA(socket,_net_socket), HA(connect,_net_connect),
    HA(__socket,_net_socket), HA(__connect,_net_connect),
    HA(send,_net_send), HA(recv,_net_recv),
    HA(__send,_net_send), HA(__recv,_net_recv),
    HA(sendto,_net_sendto), HA(recvfrom,_net_recvfrom),
    HA(__sendto,_net_sendto), HA(__recvfrom,_net_recvfrom),
    HA(shutdown,_net_shutdown),
    HA(getpeername,_net_getpeername), HA(getsockname,_net_getsockname),
    HA(setsockopt,_net_setsockopt), HA(getsockopt,_net_getsockopt),
    HA(ioctl,_net_ioctl), HA(poll,_net_poll), HA(ppoll,_net_ppoll), HA(select,_net_select),
    HA(__poll,_net_poll), HA(__ppoll,_net_ppoll), HA(__select,_net_select),
    HA(epoll_create,_net_epoll_create), HA(epoll_create1,_net_epoll_create1),
    HA(epoll_ctl,_net_epoll_ctl), HA(epoll_wait,_net_epoll_wait),
    HA(__epoll_create,_net_epoll_create), HA(__epoll_create1,_net_epoll_create1),
    HA(__epoll_ctl,_net_epoll_ctl), HA(__epoll_wait,_net_epoll_wait),
    HA(eventfd,_net_eventfd), HA(eventfd_write,_net_eventfd_write),
    HA(timerfd_create,_net_timerfd_create), HA(timerfd_settime,_net_timerfd_settime),
    HA(getaddrinfo,_net_getaddrinfo), HA(freeaddrinfo,_net_freeaddrinfo),
    HA(inet_pton,_net_inet_pton), HA(inet_ntop,_net_inet_ntop),
    HA(bind,_net_bind), HA(listen,_net_listen), HA(accept,_net_accept),
    HA(socketpair,_net_socketpair), HA(if_nametoindex,_net_if_nametoindex),

    /* math (FP args pass in XMM identically across ABIs — raw host OK) */
    H(sin), H(cos), H(tan), H(asin), H(acos), H(atan), H(atan2),
    H(sinh), H(cosh), H(tanh), H(sqrt), H(pow), H(exp), H(log), H(log2), H(log10),
    H(fabs), H(floor), H(ceil), H(round), H(fmod),
    H(sinf), H(cosf), H(tanf), H(sqrtf), H(powf), H(expf),
    H(logf), H(log2f), H(log10f), H(fabsf), H(floorf), H(ceilf),

    /* Android log */
    HA(__android_log_print,_win32_android_log_print),
    HA(__android_log_buf_print,_win32_android_log_buf_print),
    HA(__android_log_is_loggable,_win32___android_log_is_loggable),
    HA(__android_log_write,_win32_android_log_write),

    { NULL, NULL }
};

/* ── libcurl diagnostics: libmediaplatform's easy-interface calls are routed
 * through these thin sysv_abi wrappers so the VM log shows URLs and CURLcodes. */
static volatile long g_ctrace_n = 0;
#define CTRACE(...) do { if (_wtrace_on() && __atomic_fetch_add(&g_ctrace_n, 1, __ATOMIC_RELAXED) < 1500) { fprintf(stderr, __VA_ARGS__); fflush(stderr); } } while (0)
static void *_curl_real(const char *name)
{
    static void *h;
    if (!h) h = android_dlopen("libcurl.so", 2 /*RTLD_NOW*/);
    return h ? android_dlsym(h, name) : NULL;
}
typedef long (__attribute__((sysv_abi)) *_curl_f3)(void *, long, long);
typedef long (__attribute__((sysv_abi)) *_curl_f1)(void *);
typedef const char *(__attribute__((sysv_abi)) *_curl_fstr)(long);
static long __attribute__((sysv_abi)) _w_curl_easy_setopt(void *h, long opt, long arg)
{
    static _curl_f3 real; if (!real) real = (_curl_f3)_curl_real("curl_easy_setopt");
    if (opt == 10002 || opt == 10004 || opt == 10065 || opt == 10097)
        CTRACE("[curl] tid=%lu setopt h=%p opt=%ld str=%.220s\n", GetCurrentThreadId(), h, opt, arg ? (const char *)arg : "(null)");
    else if (opt < 10000)
        CTRACE("[curl] tid=%lu setopt h=%p opt=%ld val=%ld\n", GetCurrentThreadId(), h, opt, arg);
    long r = real ? real(h, opt, arg) : 48;
    if (r) CTRACE("[curl] tid=%lu setopt h=%p opt=%ld -> rc=%ld\n", GetCurrentThreadId(), h, opt, r);
    return r;
}
static long __attribute__((sysv_abi)) _w_curl_easy_perform(void *h)
{
    static _curl_f1 real; if (!real) real = (_curl_f1)_curl_real("curl_easy_perform");
    static _curl_fstr serr; if (!serr) serr = (_curl_fstr)_curl_real("curl_easy_strerror");
    CTRACE("[curl] tid=%lu perform ENTER h=%p\n", GetCurrentThreadId(), h);
    long r = real ? real(h) : 2;
    CTRACE("[curl] tid=%lu perform EXIT h=%p rc=%ld (%s)\n", GetCurrentThreadId(), h, r, serr ? serr(r) : "?");
    return r;
}
static long __attribute__((sysv_abi)) _w_curl_easy_getinfo(void *h, long info, long arg)
{
    static _curl_f3 real; if (!real) real = (_curl_f3)_curl_real("curl_easy_getinfo");
    long r = real ? real(h, info, arg) : 2;
    if (info == 0x200002 && arg) CTRACE("[curl] tid=%lu getinfo RESPONSE_CODE h=%p -> %ld\n", GetCurrentThreadId(), h, *(long *)arg);
    return r;
}

void *hybris_get_hooked_symbol(const char *sym, const char *requester)
{
    if (!sym) return NULL;
    for (int i = 0; win32_hooks[i].name; i++)
        if (strcmp(sym, win32_hooks[i].name) == 0)
            return win32_hooks[i].fn;
    for (int i = 0; win32_shim_hooks[i].name; i++)
        if (strcmp(sym, win32_shim_hooks[i].name) == 0)
            return win32_shim_hooks[i].fn;
    if (_wtrace_on() && requester && strstr(requester, "libmediaplatform")) {
        if (!strcmp(sym, "curl_easy_setopt"))  return (void *)_w_curl_easy_setopt;
        if (!strcmp(sym, "curl_easy_perform")) return (void *)_w_curl_easy_perform;
        if (!strcmp(sym, "curl_easy_getinfo")) return (void *)_w_curl_easy_getinfo;
    }
    void *r = NULL;
    if (_hybris_win32_user_hook_cb)
        r = _hybris_win32_user_hook_cb(sym, requester);
    if (!r && !(sym[0]=='_' && sym[1]=='Z') && getenv("ADAM_UNHOOKED")) { fprintf(stderr, "[unhooked] %s <- %s\n", sym, requester ? requester : "?"); fflush(stderr); }
    return r;
}
