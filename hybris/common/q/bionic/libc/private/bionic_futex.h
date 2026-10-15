/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _BIONIC_FUTEX_H
#define _BIONIC_FUTEX_H

#include <errno.h>
#if defined(_WIN32)
#include <stdint.h>
#include <time.h>
#include <windows.h>
#else
#include <linux/futex.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <sys/cdefs.h>
#if !defined(_WIN32)
#include <sys/syscall.h>
#include <unistd.h>
#endif

struct timespec;

#if defined(_WIN32)
static inline DWORD __bionic_futex_timeout(const timespec* abs_timeout) {
  if (abs_timeout == nullptr) return INFINITE;

  FILETIME file_time;
  GetSystemTimeAsFileTime(&file_time);
  const uint64_t windows_now = (static_cast<uint64_t>(file_time.dwHighDateTime) << 32) |
                               file_time.dwLowDateTime;
  // FILETIME is 100ns since 1601-01-01; timespec is ns since Unix epoch.
  const uint64_t unix_now_ns = (windows_now - UINT64_C(116444736000000000)) * 100;
  const uint64_t deadline_ns = static_cast<uint64_t>(abs_timeout->tv_sec) * UINT64_C(1000000000) +
                               static_cast<uint64_t>(abs_timeout->tv_nsec);
  if (deadline_ns <= unix_now_ns) return 0;
  const uint64_t remaining_ms = (deadline_ns - unix_now_ns + UINT64_C(999999)) / UINT64_C(1000000);
  return remaining_ms >= INFINITE ? INFINITE - 1 : static_cast<DWORD>(remaining_ms);
}

static inline int __futex_wait_ex(volatile void* ftx, bool shared, int value,
                                   bool use_realtime_clock, const timespec* abs_timeout) {
  (void)shared;
  (void)use_realtime_clock;
  for (;;) {
    if (WaitOnAddress(const_cast<void*>(ftx), &value, sizeof(value),
                      __bionic_futex_timeout(abs_timeout))) {
      return 0;
    }
    if (GetLastError() == ERROR_TIMEOUT) return -ETIMEDOUT;
    // A wakeup can race with a value change.  Re-check the value before
    // waiting again, matching FUTEX_WAIT's compare-and-sleep behavior.
    if (*static_cast<volatile const int*>(ftx) != value) return 0;
  }
}
#else
__LIBC_HIDDEN__ int __futex_wait_ex(volatile void* ftx, bool shared, int value,
                                    bool use_realtime_clock, const timespec* abs_timeout);
#endif

static inline int __futex(volatile void* ftx, int op, int value,
                                           const timespec* timeout, int bitset) {
#if defined(_WIN32)
  (void)op;
  (void)bitset;
  return __futex_wait_ex(ftx, false, value, false, timeout);
#else
  // Our generated syscall assembler sets errno, but our callers (pthread functions) don't want to.
  int saved_errno = errno;
  int result = syscall(__NR_futex, ftx, op, value, timeout, NULL, bitset);
  if ((result == -1)) {
    result = -errno;
    errno = saved_errno;
  }
  return result;
#endif
}

static inline int __futex_wake(volatile void* ftx, int count) {
#if defined(_WIN32)
  (void)count;
  WakeByAddressAll(const_cast<void*>(ftx));
  return 0;
#else
  return __futex(ftx, FUTEX_WAKE, count, nullptr, 0);
#endif
}

static inline int __futex_wake_ex(volatile void* ftx, bool shared, int count) {
#if defined(_WIN32)
  (void)shared;
  (void)count;
  WakeByAddressAll(const_cast<void*>(ftx));
  return 0;
#else
  return __futex(ftx, shared ? FUTEX_WAKE : FUTEX_WAKE_PRIVATE, count, nullptr, 0);
#endif
}

static inline int __futex_wait(volatile void* ftx, int value, const timespec* timeout) {
#if defined(_WIN32)
  return __futex_wait_ex(ftx, false, value, false, timeout);
#else
  return __futex(ftx, FUTEX_WAIT, value, timeout, 0);
#endif
}

static inline int __futex_wait_ex(volatile void* ftx, bool shared, int value) {
#if defined(_WIN32)
  (void)shared;
  return __futex_wait_ex(ftx, shared, value, false, nullptr);
#else
  return __futex(ftx, (shared ? FUTEX_WAIT_BITSET : FUTEX_WAIT_BITSET_PRIVATE), value, nullptr,
                 FUTEX_BITSET_MATCH_ANY);
#endif
}

static inline int __futex_pi_unlock(volatile void* ftx, bool shared) {
#if defined(_WIN32)
  (void)ftx;
  (void)shared;
  return -ENOSYS;
#else
  return __futex(ftx, shared ? FUTEX_UNLOCK_PI : FUTEX_UNLOCK_PI_PRIVATE, 0, nullptr, 0);
#endif
}

#if !defined(_WIN32)
__LIBC_HIDDEN__ int __futex_pi_lock_ex(volatile void* ftx, bool shared, bool use_realtime_clock,
                                       const timespec* abs_timeout);
#endif

#endif /* _BIONIC_FUTEX_H */
