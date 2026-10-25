#!/usr/bin/perl
# RECOVERY PATCH — Fix #6: hook guest mmap/munmap/mprotect to VirtualAlloc
# ---------------------------------------------------------------------------
# bionic libc's own mmap is a raw Linux syscall; executed on Windows it returns
# garbage (0xc0000005), which arc4random's _rs_allocate stored as its RNG-state
# pointer and then dereferenced, crashing in _rs_init. Hook the guest mmap
# family (sysv_abi) to VirtualAlloc, mirroring the linker's own mman.h impl.
# MAP_FIXED=0x10, PROT_READ=1/WRITE=2/EXEC=4, MAP_FAILED=(void*)-1.
use strict; use warnings;
my $C = $ENV{HYBRIS_COMMON} || '/c/libhybris-win/hybris/common';
my $HT = "$C/windows_hook_table.c";
open my $fh,'<',$HT or die "$HT: $!"; my $s = do{local $/;<$fh>}; close $fh;

my $block = <<'BLK';
static DWORD _sysv_mmap_prot(int prot){ if(prot==0)return PAGE_NOACCESS; if(prot&4)return (prot&2)?PAGE_EXECUTE_READWRITE:PAGE_EXECUTE_READ; if(prot&2)return PAGE_READWRITE; if(prot&1)return PAGE_READONLY; return PAGE_NOACCESS; }
static void *__attribute__((sysv_abi)) _sysv_mmap(void *addr,size_t len,int prot,int flags,int fd,long long off){ (void)fd;(void)off; if(len==0)return (void*)-1; if(prot==0){ void*r=VirtualAlloc(addr,len,MEM_RESERVE,PAGE_NOACCESS); if(!r&&addr)r=VirtualAlloc(NULL,len,MEM_RESERVE,PAGE_NOACCESS); return r?r:(void*)-1;} DWORD wp=_sysv_mmap_prot(prot); void*r; if(flags&0x10){ r=VirtualAlloc(addr,len,MEM_COMMIT,wp); if(r)return r;} r=VirtualAlloc(addr,len,MEM_RESERVE|MEM_COMMIT,wp); if(!r)r=VirtualAlloc(NULL,len,MEM_RESERVE|MEM_COMMIT,wp); return r?r:(void*)-1; }
static int __attribute__((sysv_abi)) _sysv_munmap(void *addr,size_t len){ if(VirtualFree(addr,len,MEM_DECOMMIT))return 0; return VirtualFree(addr,0,MEM_RELEASE)?0:-1; }
static int __attribute__((sysv_abi)) _sysv_mprotect(void *addr,size_t len,int prot){ DWORD old; DWORD wp=_sysv_mmap_prot(prot); MEMORY_BASIC_INFORMATION mbi; if(VirtualQuery(addr,&mbi,sizeof(mbi))&&mbi.State==MEM_RESERVE)return VirtualAlloc(addr,len,MEM_COMMIT,wp)?0:-1; return VirtualProtect(addr,len,wp,&old)?0:-1; }
BLK
$s =~ s/(#define HW\(sym\))/$block\n$1/ or warn "fix6: HW marker not found\n";
# register entries just before the pthread-lifecycle block of the hook array
my $ent = "    HA(mmap, _sysv_mmap),\n    HA(munmap, _sysv_munmap),\n    HA(mprotect, _sysv_mprotect),\n";
$s =~ s{(/\* .*pthread lifecycle)}{$ent$1} or warn "fix6: array anchor not found\n";
open my $o,'>',$HT or die $!; print $o $s; close $o;
print "Fix #6 (mmap family) applied.\n";
