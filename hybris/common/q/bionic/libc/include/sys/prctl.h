#ifndef HYBRIS_SYS_PRCTL_H
#define HYBRIS_SYS_PRCTL_H

#if defined(_WIN32)

#include <stdarg.h>

#define PR_SET_VMA 0x53564d41
#define PR_SET_VMA_ANON_NAME 0
#define PR_GET_DUMPABLE 3

static inline int prctl(int option, ...) {
  return option == PR_GET_DUMPABLE ? 1 : 0;
}

#else

#include_next <sys/prctl.h>

#endif

#endif
