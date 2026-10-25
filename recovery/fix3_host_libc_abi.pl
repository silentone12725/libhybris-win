#!/usr/bin/perl
# RECOVERY PATCH — Fix #3: host libc System V -> Windows ABI bridge
# ---------------------------------------------------------------------------
# Android .so code is System V; host ucrtbase/dl* functions are Windows x64.
# Calling a Windows-ABI function from guest code reads args from the wrong
# registers AND spills nonvolatile registers into the caller's absent 32-byte
# shadow space, corrupting the guest frame (this is how operator new's saved
# rbx got clobbered via ucrtbase malloc_base, and how a guest dlopen() got a
# garbage filename that crashed in do_dlopen->std::string->strlen).
#
# Does three things:
#   (a) sysv_abi allocator bridges malloc/free/calloc/realloc/malloc_usable_size
#       and memalign/posix_memalign/aligned_alloc (host 16-byte alignment); drop
#       the raw H(malloc..) duplicates.
#   (b) sysv_abi mem bridges memcpy/memmove/memset/memcmp/memchr (were raw H()).
#   (c) sysv_abi on every _safe_*/_stub_* helper; sysv_abi dl* bridges
#       dlopen/dlsym/dlclose/dlerror/dladdr/dl_iterate_phdr (android_* are the
#       Windows-ABI impls our C keeps calling directly).
use strict; use warnings;
my $C = $ENV{HYBRIS_COMMON} || '/c/libhybris-win/hybris/common';
my $HT = "$C/windows_hook_table.c";
open my $fh,'<',$HT or die "$HT: $!"; my $s = do{local $/;<$fh>}; close $fh;

# (c1) sysv_abi on _safe_*/_stub_* helpers
$s =~ s/^(static\s+)(?!__attribute__)(.*?\b(?:_safe_|_stub_)\w+\s*\()/$1__attribute__((sysv_abi)) $2/gm;

# wrappers inserted before "#define HW(sym)"
my $block = <<'BLK';
#include <malloc.h>
static void *__attribute__((sysv_abi)) _sysv_malloc(size_t n){return malloc(n);}
static void  __attribute__((sysv_abi)) _sysv_free(void *p){free(p);}
static void *__attribute__((sysv_abi)) _sysv_calloc(size_t a,size_t b){return calloc(a,b);}
static void *__attribute__((sysv_abi)) _sysv_realloc(void *p,size_t n){return realloc(p,n);}
static size_t __attribute__((sysv_abi)) _sysv_malloc_usable_size(void *p){return p?_msize(p):0;}
static void *__attribute__((sysv_abi)) _sysv_memalign(size_t al,size_t n){(void)al;return malloc(n);}
static int __attribute__((sysv_abi)) _sysv_posix_memalign(void **o,size_t al,size_t n){(void)al; if(!o)return 22; void*p=malloc(n); if(!p)return 12; *o=p; return 0;}
static void *__attribute__((sysv_abi)) _sysv_aligned_alloc(size_t al,size_t n){(void)al;return malloc(n);}
static void *__attribute__((sysv_abi)) _sysv_memcpy(void *d,const void *s,size_t n){return memcpy(d,s,n);}
static void *__attribute__((sysv_abi)) _sysv_memmove(void *d,const void *s,size_t n){return memmove(d,s,n);}
static void *__attribute__((sysv_abi)) _sysv_memset(void *d,int c,size_t n){return memset(d,c,n);}
static int   __attribute__((sysv_abi)) _sysv_memcmp(const void *a,const void *b,size_t n){return memcmp(a,b,n);}
static void *__attribute__((sysv_abi)) _sysv_memchr(const void *p,int c,size_t n){return memchr(p,c,n);}
/* android_dl* are declared earlier in this file; do not re-declare. */
static void *__attribute__((sysv_abi)) _sysv_dlopen(const char *f,int fl){return android_dlopen(f,fl);}
static void *__attribute__((sysv_abi)) _sysv_dlsym(void *h,const char *s){return android_dlsym(h,s);}
static int   __attribute__((sysv_abi)) _sysv_dlclose(void *h){return android_dlclose(h);}
static char *__attribute__((sysv_abi)) _sysv_dlerror(void){return android_dlerror();}
static int   __attribute__((sysv_abi)) _sysv_dladdr(const void *a,void *i){return android_dladdr(a,i);}
static int   __attribute__((sysv_abi)) _sysv_dl_iterate_phdr(void *cb,void *d){return android_dl_iterate_phdr((int(*)(void*,size_t,void*))cb,d);}
BLK
$s =~ s/(#define HW\(sym\))/$block\n$1/ or warn "fix3: HW marker not found\n";

# (a) replace raw malloc-family H() entries (our sysv_abi entries are added below)
$s =~ s/H\(malloc\),\s*H\(free\),\s*H\(calloc\),\s*H\(realloc\),/HA(malloc,_sysv_malloc), HA(free,_sysv_free), HA(calloc,_sysv_calloc), HA(realloc,_sysv_realloc),\n    HA(malloc_usable_size,_sysv_malloc_usable_size), HA(memalign,_sysv_memalign), HA(posix_memalign,_sysv_posix_memalign), HA(aligned_alloc,_sysv_aligned_alloc),/;
# (b) replace raw mem-family H() entries
$s =~ s/H\(memcpy\),\s*H\(memmove\),\s*H\(memset\),\s*H\(memcmp\),\s*H\(memchr\),/HA(memcpy,_sysv_memcpy), HA(memmove,_sysv_memmove), HA(memset,_sysv_memset), HA(memcmp,_sysv_memcmp), HA(memchr,_sysv_memchr),/;
# (c2) dl* entries -> sysv_abi bridges
for my $p (['dlopen','_sysv_dlopen'],['dlsym','_sysv_dlsym'],['dlclose','_sysv_dlclose'],['dlerror','_sysv_dlerror'],['dladdr','_sysv_dladdr'],['dl_iterate_phdr','_sysv_dl_iterate_phdr']) {
  $s =~ s/HA\(\Q$p->[0]\E,\s*android_\w+\)/HA($p->[0], $p->[1])/;
}
open my $o,'>',$HT or die $!; print $o $s; close $o;
print "Fix #3 (host libc ABI) applied.\n";
