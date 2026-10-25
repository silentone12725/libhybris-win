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
static int __attribute__((sysv_abi)) _bionic_mutex_init(volatile int32_t *m, const void *attr)
{ if (!m) return EINVAL; (void)attr; __atomic_store_n(m, 0, __ATOMIC_RELEASE); return 0; }
static int __attribute__((sysv_abi)) _bionic_mutex_destroy(volatile int32_t *m) { (void)m; return 0; }
static int __attribute__((sysv_abi)) _bionic_mutex_lock(volatile int32_t *m)
{
    int32_t old;
    if (!m) return EINVAL;
    old = 0;
    if (__atomic_compare_exchange_n(m, &old, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return 0;
    for (;;) {
        int32_t state = __atomic_load_n(m, __ATOMIC_RELAXED);
        if (state == 0) {
            old = 0;
            if (__atomic_compare_exchange_n(m, &old, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) return 0;
        }
        SwitchToThread();
    }
}
static int __attribute__((sysv_abi)) _bionic_mutex_trylock(volatile int32_t *m)
{ int32_t old; if (!m) return EINVAL; old = 0;
  return __atomic_compare_exchange_n(m, &old, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED) ? 0 : EBUSY; }
static int __attribute__((sysv_abi)) _bionic_mutex_unlock(volatile int32_t *m)
{ if (!m) return EINVAL; __atomic_store_n(m, 0, __ATOMIC_RELEASE); return 0; }
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
{ (void)attr; struct _bionic_thread_tramp *t=(struct _bionic_thread_tramp*)malloc(sizeof *t); if(!t) return EAGAIN;
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
static int *__attribute__((sysv_abi)) _win32_errno_location(void){ return _errno(); }

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
    HA(__errno_location,_win32_errno_location),

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
