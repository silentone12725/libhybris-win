#ifndef HYBRIS_WINDOWS_SYS_MMAN_H
#define HYBRIS_WINDOWS_SYS_MMAN_H

#if defined(_WIN32)

#include <windows.h>
#include <stddef.h>

#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 0x02
#define MAP_SHARED 0x01
#define MAP_ANONYMOUS 0x20
#define MAP_NORESERVE 0x4000
#define MAP_FAILED ((void*)-1)

static inline DWORD hybris_mmap_protection(int prot) {
  if ((prot & PROT_EXEC) != 0) {
    return (prot & PROT_WRITE) != 0 ? PAGE_EXECUTE_READWRITE :
           ((prot & PROT_READ) != 0 ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
  }
  if ((prot & PROT_WRITE) != 0) return PAGE_READWRITE;
  if ((prot & PROT_READ) != 0) return PAGE_READONLY;
  return PAGE_NOACCESS;
}

static inline void* mmap(void* address, size_t length, int prot, int flags,
                         int fd, long long offset) {
  (void)flags;
  (void)fd;
  (void)offset;
  if (length == 0) return MAP_FAILED;
  return VirtualAlloc(address, length, MEM_RESERVE | MEM_COMMIT,
                      hybris_mmap_protection(prot));
}

static inline int munmap(void* address, size_t length) {
  (void)length;
  return VirtualFree(address, 0, MEM_RELEASE) ? 0 : -1;
}

static inline int mprotect(void* address, size_t length, int prot) {
  DWORD old_protection;
  return VirtualProtect(address, length, hybris_mmap_protection(prot), &old_protection)
             ? 0
             : -1;
}

#else

#include_next <sys/mman.h>

#endif

#endif
