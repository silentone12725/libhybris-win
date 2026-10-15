#ifndef WINDOWS_POSIX_COMPAT_H
#define WINDOWS_POSIX_COMPAT_H

#if defined(_WIN32)

#include <windows.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <io.h>

static inline char* hybris_windows_basename(const char* path) {
  const char* start = path;
  const char* cursor;
  if (path == nullptr) return nullptr;
  for (cursor = path; *cursor != '\0'; ++cursor) {
    if (*cursor == '/' || *cursor == '\\') start = cursor + 1;
  }
  return const_cast<char*>(start);
}

static inline char* hybris_windows_stpcpy(char* destination, const char* source) {
  const size_t length = strlen(source);
  memcpy(destination, source, length + 1);
  return destination + length;
}

static inline char* hybris_windows_realpath(const char* path, char* resolved) {
  if (path == nullptr || resolved == nullptr || _fullpath(resolved, path, PATH_MAX) == nullptr) {
    errno = ENOENT;
    return nullptr;
  }
  for (char* cursor = resolved; *cursor != '\0'; ++cursor) {
    if (*cursor == '\\') *cursor = '/';
  }
  return resolved;
}

static inline int hybris_windows_readlink(const char* path, char* buffer, size_t size) {
  DWORD length;
  if (path == nullptr || buffer == nullptr || size == 0 || strcmp(path, "/proc/self/exe") != 0) {
    errno = ENOSYS;
    return -1;
  }
  length = GetModuleFileNameA(nullptr, buffer, (DWORD)(size - 1));
  if (length == 0 || length >= size - 1) {
    errno = ENAMETOOLONG;
    return -1;
  }
  buffer[length] = '\0';
  return (int)length;
}

static inline int hybris_windows_dprintf(int fd, const char* format, ...) {
  va_list args;
  FILE* stream = fd == 2 ? stderr : stdout;
  int result;
  va_start(args, format);
  result = vfprintf(stream, format, args);
  va_end(args);
  return result;
}

#ifndef DEFAULT_HYBRIS_LD_LIBRARY_PATH
#define DEFAULT_HYBRIS_LD_LIBRARY_PATH "/system/lib64:/vendor/lib64:/odm/lib64"
#endif

#define basename hybris_windows_basename
#define stpcpy hybris_windows_stpcpy
#define realpath hybris_windows_realpath
#define readlink hybris_windows_readlink
#define dprintf hybris_windows_dprintf

#endif

#endif
