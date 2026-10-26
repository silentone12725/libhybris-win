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
#include <time.h>

/* Win32 pthread wrappers (static functions). */
#include "hooks_win32.c"

/* User-supplied fallback callback from windows_core_hooks.c. */
extern hybris_hook_cb _hybris_win32_user_hook_cb;

/* Android dl* functions from windows_core_hooks.c (Windows ABI). */
extern void *android_dlopen(const char *, int);
extern void *android_dlsym(void *, const char *);
extern int   android_dlclose(void *);
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
static int __attribute__((sysv_abi)) _bionic_cond_init(void *cond, const void *attr)
{ if (!cond) return EINVAL; (void)attr; _bionic_cond_impl_t *d = (_bionic_cond_impl_t *)malloc(sizeof *d);
  if (!d) return ENOMEM; InitializeCriticalSection(&d->cs); InitializeConditionVariable(&d->cv);
  *(uintptr_t *)cond = (uintptr_t)d; return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_destroy(void *cond)
{ if (!cond) return EINVAL; _bionic_cond_impl_t *d = (_bionic_cond_impl_t *)(*(uintptr_t *)cond);
  if (!d) return 0; DeleteCriticalSection(&d->cs); free(d); *(uintptr_t *)cond = 0; return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_signal(void *cond)
{ if (!cond) return EINVAL; _bionic_cond_impl_t *d = (_bionic_cond_impl_t *)(*(uintptr_t *)cond);
  if (!d) return EINVAL; WakeConditionVariable(&d->cv); return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_broadcast(void *cond)
{ if (!cond) return EINVAL; _bionic_cond_impl_t *d = (_bionic_cond_impl_t *)(*(uintptr_t *)cond);
  if (!d) return EINVAL; WakeAllConditionVariable(&d->cv); return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_wait(void *cond, volatile int32_t *m)
{ if (!cond || !m) return EINVAL; _bionic_cond_impl_t *d = (_bionic_cond_impl_t *)(*(uintptr_t *)cond);
  if (!d) return EINVAL; _bionic_mutex_unlock(m); EnterCriticalSection(&d->cs);
  SleepConditionVariableCS(&d->cv, &d->cs, INFINITE); LeaveCriticalSection(&d->cs);
  _bionic_mutex_lock(m); return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_timedwait(void *cond, volatile int32_t *m, const struct timespec *ts)
{ if (!cond || !m) return EINVAL; _bionic_cond_impl_t *d = (_bionic_cond_impl_t *)(*(uintptr_t *)cond);
  if (!d) return EINVAL; DWORD ms = INFINITE;
  if (ts) { struct timespec now; clock_gettime(CLOCK_REALTIME, &now);
    long long diff = ((long long)ts->tv_sec - now.tv_sec) * 1000LL + ((long long)ts->tv_nsec - now.tv_nsec) / 1000000LL;
    if (diff <= 0) return ETIMEDOUT; ms = (DWORD)diff; }
  _bionic_mutex_unlock(m); EnterCriticalSection(&d->cs);
  BOOL ok = SleepConditionVariableCS(&d->cv, &d->cs, ms); LeaveCriticalSection(&d->cs);
  _bionic_mutex_lock(m); return ok ? 0 : ETIMEDOUT; }

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
  void*(__attribute__((sysv_abi))*fn)(void*)=(void*(__attribute__((sysv_abi))*)(void*))t->fn; void*arg=t->arg; free(t); return fn(arg); }
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
    case 202: { static volatile long fc=0; long c=++fc; if((c%200000)==1) fprintf(stderr,"[futex] call #%ld op=%ld uaddr=%p\n",c,a2,(void*)a1); return 0; }  /* __NR_futex: diagnostic spin counter */
    case 234: return 0;                                    /* __NR_tgkill */
    default:  errno = 38 /*ENOSYS*/; return -1;
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
    return _open(path, wf, mode ? mode : 0666);
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
    if (_is_ur(fd)){ if (!SystemFunction036(buf,(unsigned long)n)) return -1; return (long)n; }
    return _read(fd, buf, (unsigned)n);
}
static long __attribute__((sysv_abi)) _sysv_write(int fd, const void *buf, size_t n){ return _write(fd, buf, (unsigned)n); }
static int __attribute__((sysv_abi)) _sysv_close(int fd){
    for (long i=0;i<g_urn;i++) if (g_ur[i]==fd){ g_ur[i]=g_ur[--g_urn]; break; }
    return _close(fd);
}
static long long __attribute__((sysv_abi)) _sysv_lseek(int fd, long long off, int whence){
    if (_is_ur(fd)) return 0;
    return _lseeki64(fd, off, whence);
}

/* Diagnostic: log the C++ exception type when guest code throws, then abort.
 * A guest throw can't unwind through the host (Windows PE) frames of the wrapper
 * anyway, so this reports the type instead of crashing opaquely in the unwinder. */
static void __attribute__((sysv_abi)) _log_cxa_throw(void *exc, void *tinfo, void *dtor){
    (void)dtor;
    const char *nm = "(null type_info)";
    if (tinfo) { const char *n = *(const char * const *)((const char *)tinfo + 8); if (n) nm = n; }
    fprintf(stderr, "[cxa_throw] type=%s exc=%p\n", nm, exc);
    /* std::runtime_error/system_error: a message char* at +8, and for
     * system_error an error_code {int __val_; category*} at +16. */
    if (exc) {
        const char *msg = *(const char * const *)((const char *)exc + 8);
        int val = *(const int *)((const char *)exc + 16);
        if (msg && (uintptr_t)msg >= 0x10000)
            fprintf(stderr, "[cxa_throw]   what=\"%s\" code=%d\n", msg, val);
        else
            fprintf(stderr, "[cxa_throw]   code=%d\n", val);
    }
    fflush(stderr);
    abort();
}

/* ── mmap family (guest -> VirtualAlloc, sysv_abi) ──────────────────────── */
static DWORD _mprot(int prot){ if(prot==0)return PAGE_NOACCESS; if(prot&4)return (prot&2)?PAGE_EXECUTE_READWRITE:PAGE_EXECUTE_READ; if(prot&2)return PAGE_READWRITE; if(prot&1)return PAGE_READONLY; return PAGE_NOACCESS; }
static void *__attribute__((sysv_abi)) _sysv_mmap(void *addr,size_t len,int prot,int flags,int fd,long long off)
{ (void)fd;(void)off; if(len==0)return (void*)-1;
  if(prot==0){ void*r=VirtualAlloc(addr,len,MEM_RESERVE,PAGE_NOACCESS); if(!r&&addr)r=VirtualAlloc(NULL,len,MEM_RESERVE,PAGE_NOACCESS); return r?r:(void*)-1; }
  DWORD wp=_mprot(prot); void*r; if(flags&0x10){ r=VirtualAlloc(addr,len,MEM_COMMIT,wp); if(r)return r; }
  r=VirtualAlloc(addr,len,MEM_RESERVE|MEM_COMMIT,wp); if(!r)r=VirtualAlloc(NULL,len,MEM_RESERVE|MEM_COMMIT,wp); return r?r:(void*)-1; }
static int __attribute__((sysv_abi)) _sysv_munmap(void *addr,size_t len){ if(VirtualFree(addr,len,MEM_DECOMMIT))return 0; return VirtualFree(addr,0,MEM_RELEASE)?0:-1; }
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
static int __attribute__((sysv_abi)) _win32_android_log_print(int prio,const char *tag,const char *fmt,...){(void)prio;(void)tag;(void)fmt;return 0;}
static int __attribute__((sysv_abi)) _win32_android_log_buf_print(int buf,int prio,const char *tag,const char *fmt,...){(void)buf;(void)prio;(void)tag;(void)fmt;return 0;}
static int __attribute__((sysv_abi)) _win32___android_log_is_loggable(int p,const char *t,int d){(void)p;(void)t;(void)d;return 1;}

struct _w32_hook { const char *name; void *fn; };
#define H(sym)        { #sym,  (void *)(sym) }          /* raw host (FP-only math) */
#define HW(sym)       { #sym,  (void *)(_hybris_win32_##sym) }
#define HA(sym, fn)   { #sym,  (void *)(fn) }

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
    HA(sprintf,_v_fnoprint), HA(vsprintf,(void*)_v_fnoprint),
    HA(snprintf,_sysv_snprintf), HA(vsnprintf,_sysv_vsnprintf),
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
    HA(__cxa_throw,_log_cxa_throw),  /* diagnostic: log thrown C++ exception type */
    /* POSIX file I/O via the host CRT; /dev/urandom from the Windows RNG. */
    HA(open,_sysv_open), HA(open64,_sysv_open), HA(openat,_sysv_openat),
    HA(__open_2,_sysv_open_2),
    HA(read,_sysv_read), HA(write,_sysv_write), HA(close,_sysv_close),
    HA(lseek,_sysv_lseek), HA(lseek64,_sysv_lseek),

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
    HA(__android_log_write,_win32_android_log_print),

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
