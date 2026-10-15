#ifndef HYBRIS_SYS_AUXV_H
#define HYBRIS_SYS_AUXV_H

#if defined(_WIN32)

#include <stdint.h>

#define AT_PHDR 3
#define AT_NULL 0
#define AT_PHNUM 5
#define AT_ENTRY 9
#define AT_BASE 7
#define AT_SECURE 23
#define AT_SYSINFO_EHDR 33
#define AT_PAGESZ 6

static inline unsigned long getauxval(unsigned long type) {
  (void)type;
  return 0;
}

#else

#include_next <sys/auxv.h>

#endif

#endif
