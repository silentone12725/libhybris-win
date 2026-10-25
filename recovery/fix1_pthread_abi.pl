#!/usr/bin/perl
# RECOVERY PATCH — Fix #1: pthread System V -> Windows ABI bridge
# ---------------------------------------------------------------------------
# Context: the build VM was re-imaged and its ~900-line windows_hook_table.c
# (plus the 7 session commits) were lost (never pushed). This file reproduces
# the pthread ABI fix verbatim so it can be re-applied after the hook table is
# rebuilt. Root cause: Android .so code is System V AMD64; the Windows hook
# implementations behind the hook table are Windows x64. Every pthread hook was
# reading its first arg from the wrong register, and bionic's cond/rwlock/attr
# structs differ from winpthread's, so the raw HA(fn,fn) entries were doubly
# wrong.
#
# Apply order within Fix #1: this script does all of it:
#   (a) add __attribute__((sysv_abi)) to every _hybris_win32_* wrapper
#       (hooks_win32.c) and every _bionic_mutex_* / _bionic_pthread_once
#       (windows_hook_table.c);
#   (b) add bionic-compatible _bionic_cond_* (CRITICAL_SECTION/CONDITION_VARIABLE
#       over the bionic spinlock mutex), _bionic_rwlock_*, _bionic_attr_*, a
#       _bionic_pthread_create ABI trampoline, and pthread_kill/pthread_sigmask
#       stubs;
#   (c) point the pthread_cond_*/rwlock_*/attr_*/create/kill/sigmask hook-table
#       entries at those wrappers.
# ALSO (separate, do by hand): add "libstoreservicescore.so" to the
# ctor_whitelist[] in linker_soinfo.cpp so its DT_INIT_ARRAY constructors run.
use strict; use warnings;
my $C = $ENV{HYBRIS_COMMON} || '/c/libhybris-win/hybris/common';
my $HT = "$C/windows_hook_table.c";
my $HW = "$C/hooks_win32.c";

# (a) sysv_abi on all _hybris_win32_* wrappers
{
  open my $fh,'<',$HW or die "$HW: $!"; my $s = do{local $/;<$fh>}; close $fh;
  $s =~ s/^(static\s+)(?!.*__attribute__\(\(sysv_abi\)\))([a-zA-Z_][\w*\s]*?\s+_hybris_win32_)/$1__attribute__((sysv_abi)) $2/gmx;
  open my $o,'>',$HW or die $!; print $o $s; close $o;
}

# (a) sysv_abi on _bionic_mutex_* / _bionic_pthread_once, then (b)+(c)
{
  open my $fh,'<',$HT or die "$HT: $!"; my $s = do{local $/;<$fh>}; close $fh;

  # (a) sysv_abi on existing _bionic_* helpers
  $s =~ s/^(static\s+)(?!__attribute__)(.*?\b_bionic_\w+\s*\()/$1__attribute__((sysv_abi)) $2/gm;

  # (b) wrapper block inserted before the "#define HW(sym)" macro
  my $block = <<'BLK';
#include <windows.h>
typedef struct _bionic_cond_impl { CRITICAL_SECTION cs; CONDITION_VARIABLE cv; } _bionic_cond_impl_t;
static int __attribute__((sysv_abi)) _bionic_cond_init(void *cond, const void *attr){ if(!cond)return EINVAL;(void)attr; _bionic_cond_impl_t*d=(_bionic_cond_impl_t*)malloc(sizeof*d); if(!d)return ENOMEM; InitializeCriticalSection(&d->cs); InitializeConditionVariable(&d->cv); *(uintptr_t*)cond=(uintptr_t)d; return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_destroy(void *cond){ if(!cond)return EINVAL; _bionic_cond_impl_t*d=(_bionic_cond_impl_t*)(*(uintptr_t*)cond); if(!d)return 0; DeleteCriticalSection(&d->cs); free(d); *(uintptr_t*)cond=0; return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_signal(void *cond){ if(!cond)return EINVAL; _bionic_cond_impl_t*d=(_bionic_cond_impl_t*)(*(uintptr_t*)cond); if(!d)return EINVAL; WakeConditionVariable(&d->cv); return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_broadcast(void *cond){ if(!cond)return EINVAL; _bionic_cond_impl_t*d=(_bionic_cond_impl_t*)(*(uintptr_t*)cond); if(!d)return EINVAL; WakeAllConditionVariable(&d->cv); return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_wait(void *cond, volatile int32_t *m){ if(!cond||!m)return EINVAL; _bionic_cond_impl_t*d=(_bionic_cond_impl_t*)(*(uintptr_t*)cond); if(!d)return EINVAL; _bionic_mutex_unlock(m); EnterCriticalSection(&d->cs); SleepConditionVariableCS(&d->cv,&d->cs,INFINITE); LeaveCriticalSection(&d->cs); _bionic_mutex_lock(m); return 0; }
static int __attribute__((sysv_abi)) _bionic_cond_timedwait(void *cond, volatile int32_t *m, const struct timespec *ts){ if(!cond||!m)return EINVAL; _bionic_cond_impl_t*d=(_bionic_cond_impl_t*)(*(uintptr_t*)cond); if(!d)return EINVAL; DWORD ms=INFINITE; if(ts){ struct timespec now; clock_gettime(CLOCK_REALTIME,&now); long long diff=((long long)ts->tv_sec-now.tv_sec)*1000LL+((long long)ts->tv_nsec-now.tv_nsec)/1000000LL; if(diff<=0)return ETIMEDOUT; ms=(DWORD)diff;} _bionic_mutex_unlock(m); EnterCriticalSection(&d->cs); BOOL ok=SleepConditionVariableCS(&d->cv,&d->cs,ms); LeaveCriticalSection(&d->cs); _bionic_mutex_lock(m); return ok?0:ETIMEDOUT; }
static int __attribute__((sysv_abi)) _bionic_rwlock_init(void *rw,const void *a){(void)a;return pthread_rwlock_init((pthread_rwlock_t*)rw,NULL);}
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
static void *_bionic_thread_entry(void *p){ struct _bionic_thread_tramp*t=(struct _bionic_thread_tramp*)p; void*(__attribute__((sysv_abi))*fn)(void*)=(void*(__attribute__((sysv_abi))*)(void*))t->fn; void*arg=t->arg; free(t); return fn(arg); }
static int __attribute__((sysv_abi)) _bionic_pthread_create(void *tid,const void *attr,void *(*fn)(void*),void *arg){ (void)attr; struct _bionic_thread_tramp*t=(struct _bionic_thread_tramp*)malloc(sizeof*t); if(!t)return EAGAIN; t->fn=fn; t->arg=arg; int rc=pthread_create((pthread_t*)tid,NULL,_bionic_thread_entry,t); if(rc)free(t); return rc; }
static void *__attribute__((sysv_abi)) _bionic_getspecific(pthread_key_t k){return pthread_getspecific(k);}
static int __attribute__((sysv_abi)) _bionic_pthread_kill(pthread_t th,int sig){(void)th;(void)sig;return 0;}
static int __attribute__((sysv_abi)) _bionic_pthread_sigmask(int how,const void *set,void *old){(void)how;(void)set;(void)old;return 0;}
BLK
  $s =~ s/(#define HW\(sym\))/$block\n$1/ or warn "fix1: HW marker not found\n";

  # (c) hook-table entries -> our wrappers
  my %map = (
    'pthread_cond_init'=>'_bionic_cond_init','pthread_cond_destroy'=>'_bionic_cond_destroy',
    'pthread_cond_broadcast'=>'_bionic_cond_broadcast','pthread_cond_signal'=>'_bionic_cond_signal',
    'pthread_cond_wait'=>'_bionic_cond_wait','pthread_cond_timedwait'=>'_bionic_cond_timedwait',
    'pthread_rwlock_init'=>'_bionic_rwlock_init','pthread_rwlock_destroy'=>'_bionic_rwlock_destroy',
    'pthread_rwlock_rdlock'=>'_bionic_rwlock_rdlock','pthread_rwlock_wrlock'=>'_bionic_rwlock_wrlock',
    'pthread_rwlock_unlock'=>'_bionic_rwlock_unlock','pthread_rwlock_tryrdlock'=>'_bionic_rwlock_tryrdlock',
    'pthread_rwlock_trywrlock'=>'_bionic_rwlock_trywrlock',
    'pthread_attr_init'=>'_bionic_attr_init','pthread_attr_destroy'=>'_bionic_attr_destroy',
    'pthread_attr_setdetachstate'=>'_bionic_attr_setdetachstate','pthread_attr_getdetachstate'=>'_bionic_attr_getdetachstate',
    'pthread_attr_setstacksize'=>'_bionic_attr_setstacksize','pthread_attr_getstacksize'=>'_bionic_attr_getstacksize',
    'pthread_attr_setschedpolicy'=>'_bionic_attr_setschedpolicy','pthread_attr_getschedpolicy'=>'_bionic_attr_getschedpolicy',
    'pthread_attr_setschedparam'=>'_bionic_attr_setschedparam','pthread_attr_getschedparam'=>'_bionic_attr_getschedparam',
    'pthread_create'=>'_bionic_pthread_create','pthread_getspecific'=>'_bionic_getspecific',
    'pthread_kill'=>'_bionic_pthread_kill','pthread_sigmask'=>'_bionic_pthread_sigmask',
  );
  for my $k (sort keys %map){ $s =~ s/HA\(\Q$k\E,\s*\w+\)/HA($k, $map{$k})/g; }
  open my $o,'>',$HT or die $!; print $o $s; close $o;
}
print "Fix #1 (pthread ABI) applied. REMEMBER: also add \"libstoreservicescore.so\"\n";
print "to ctor_whitelist[] in q/linker_soinfo.cpp (its DT_INIT_ARRAY must run).\n";
