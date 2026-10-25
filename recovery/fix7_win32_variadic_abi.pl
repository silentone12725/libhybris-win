#!/usr/bin/perl
# RECOVERY PATCH — Fix #7: sysv_abi on variadic _win32_* hooks
# ---------------------------------------------------------------------------
# _win32_android_log_print and the other variadic no-op _win32_* hooks were
# Windows-ABI. A variadic Windows-ABI prologue spills RCX/RDX/R8/R9 into the
# caller's 32-byte shadow space, which System V guest callers never allocate.
# A tail-called log hook therefore clobbered the caller's return address and
# "returned" into the string table (privileged-instruction fault at the format
# string). Mark the _win32_* hooks sysv_abi so the register save area lives in
# the callee frame. (This is what finally let FootHillConfig::config complete
# and advance init to DeviceGUID::instance / configure.)
use strict; use warnings;
my $C = $ENV{HYBRIS_COMMON} || '/c/libhybris-win/hybris/common';
my $HT = "$C/windows_hook_table.c";
open my $fh,'<',$HT or die "$HT: $!"; my @l=<$fh>; close $fh;
my $n=0;
for my $i (0..$#l){
  if ($l[$i] =~ /^static\s/ && $l[$i] =~ /\b_win32_\w+\s*\(/ && $l[$i] !~ /sysv_abi/){
    $l[$i] =~ s/^(static\s+)/$1__attribute__((sysv_abi)) /; $n++;
  }
}
open my $o,'>',$HT or die $!; print $o @l; close $o;
print "Fix #7: sysv_abi added to $n _win32_* hooks.\n";
