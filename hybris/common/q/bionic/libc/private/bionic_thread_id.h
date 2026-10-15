/* Small platform adapter for code that needs the native current thread id. */
#pragma once

#include <sys/types.h>

#if defined(_WIN32)
#include <windows.h>

static inline pid_t bionic_get_thread_id() {
  return static_cast<pid_t>(GetCurrentThreadId());
}
#else
#include <sys/syscall.h>
#include <unistd.h>

static inline pid_t bionic_get_thread_id() {
  return static_cast<pid_t>(syscall(__NR_gettid));
}
#endif
