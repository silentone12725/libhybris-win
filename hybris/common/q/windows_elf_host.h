#ifndef WINDOWS_ELF_HOST_H
#define WINDOWS_ELF_HOST_H

#include <windows.h>

#include <stdint.h>
#include <stddef.h>

/*
 * Narrow Windows host operations for the retained ELF linker.  This header
 * deliberately does not include the Android NDK sysroot or expose POSIX file
 * descriptor semantics.
 */

typedef struct {
    HANDLE handle;
    uint64_t size;
} win_elf_file;

typedef struct {
    unsigned char *base;
    size_t size;
    unsigned char *allocation_base;
    size_t allocation_size;
} win_elf_image;

#ifdef __cplusplus
extern "C" {
#endif

int win_elf_file_open(const char *path, win_elf_file *file);
int win_elf_file_read_at(const win_elf_file *file, void *buffer, size_t size,
                         uint64_t offset);
void win_elf_file_close(win_elf_file *file);

int win_elf_image_reserve(win_elf_image *image, size_t size);
int win_elf_image_reserve_aligned(win_elf_image *image, size_t size, size_t alignment);
int win_elf_image_commit(win_elf_image *image, size_t offset, size_t size);
int win_elf_image_protect(win_elf_image *image, size_t offset, size_t size,
                          uint32_t elf_flags);
int win_elf_image_release(win_elf_image *image);

DWORD win_elf_protection_for_flags(uint32_t elf_flags);

#ifdef __cplusplus
}
#endif

#endif
