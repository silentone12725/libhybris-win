#include "windows_elf_host.h"

#include <limits.h>
#include <string.h>

enum {
    ELF_PF_X = 1,
    ELF_PF_W = 2,
    ELF_PF_R = 4
};

int win_elf_file_open(const char *path, win_elf_file *file) {
    LARGE_INTEGER size;
    HANDLE handle;

    memset(file, 0, sizeof(*file));
    file->handle = INVALID_HANDLE_VALUE;
    handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                         FILE_FLAG_OVERLAPPED, NULL);
    if (handle == INVALID_HANDLE_VALUE || !GetFileSizeEx(handle, &size) ||
        size.QuadPart < 0) {
        if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        return 0;
    }
    file->handle = handle;
    file->size = (uint64_t)size.QuadPart;
    return 1;
}

int win_elf_file_read_at(const win_elf_file *file, void *buffer, size_t size,
                         uint64_t offset) {
    OVERLAPPED overlapped;
    HANDLE event;
    DWORD bytes_read = 0;
    int ok;

    if (file == NULL || file->handle == NULL || file->handle == INVALID_HANDLE_VALUE ||
        buffer == NULL || size > UINT32_MAX || offset > UINT64_MAX - size ||
        offset + size > file->size) return 0;
    memset(&overlapped, 0, sizeof(overlapped));
    overlapped.Offset = (DWORD)(offset & 0xffffffffu);
    overlapped.OffsetHigh = (DWORD)(offset >> 32);
    event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (event == NULL) return 0;
    overlapped.hEvent = event;
    ok = ReadFile(file->handle, buffer, (DWORD)size, &bytes_read, &overlapped);
    if (!ok && GetLastError() == ERROR_IO_PENDING) {
        ok = WaitForSingleObject(event, INFINITE) == WAIT_OBJECT_0 &&
             GetOverlappedResult(file->handle, &overlapped, &bytes_read, FALSE);
    }
    CloseHandle(event);
    return ok && bytes_read == (DWORD)size;
}

void win_elf_file_close(win_elf_file *file) {
    if (file->handle != NULL && file->handle != INVALID_HANDLE_VALUE) {
        CloseHandle(file->handle);
    }
    file->handle = INVALID_HANDLE_VALUE;
    file->size = 0;
}

int win_elf_image_reserve(win_elf_image *image, size_t size) {
    memset(image, 0, sizeof(*image));
    image->base = (unsigned char *)VirtualAlloc(NULL, size, MEM_RESERVE, PAGE_NOACCESS);
    if (image->base == NULL) return 0;
    image->size = size;
    image->allocation_base = image->base;
    image->allocation_size = size;
    return 1;
}

int win_elf_image_reserve_aligned(win_elf_image *image, size_t size, size_t alignment) {
    unsigned char *allocation;
    uintptr_t aligned;
    size_t reservation_size;

    if (alignment == 0 || (alignment & (alignment - 1)) != 0 ||
        size > SIZE_MAX - (alignment - 1)) return 0;
    reservation_size = size + alignment - 1;
    memset(image, 0, sizeof(*image));
    allocation = (unsigned char *)VirtualAlloc(NULL, reservation_size,
                                               MEM_RESERVE, PAGE_NOACCESS);
    if (allocation == NULL) return 0;
    aligned = ((uintptr_t)allocation + alignment - 1) & ~(uintptr_t)(alignment - 1);
    image->base = (unsigned char *)aligned;
    image->size = size;
    image->allocation_base = allocation;
    image->allocation_size = reservation_size;
    return 1;
}

int win_elf_image_commit(win_elf_image *image, size_t offset, size_t size) {
    if (offset > image->size || size > image->size - offset ||
        (offset & 4095u) != 0 || (size & 4095u) != 0) return 0;
    return VirtualAlloc(image->base + offset, size, MEM_COMMIT, PAGE_READWRITE) != NULL;
}

DWORD win_elf_protection_for_flags(uint32_t elf_flags) {
    switch (elf_flags & (ELF_PF_R | ELF_PF_W | ELF_PF_X)) {
        case ELF_PF_X: return PAGE_EXECUTE;
        case ELF_PF_R: return PAGE_READONLY;
        case ELF_PF_W: return PAGE_READWRITE;
        case ELF_PF_R | ELF_PF_X: return PAGE_EXECUTE_READ;
        case ELF_PF_W | ELF_PF_X: return PAGE_EXECUTE_READWRITE;
        case ELF_PF_R | ELF_PF_W: return PAGE_READWRITE;
        case ELF_PF_R | ELF_PF_W | ELF_PF_X: return PAGE_EXECUTE_READWRITE;
        default: return PAGE_NOACCESS;
    }
}

int win_elf_image_protect(win_elf_image *image, size_t offset, size_t size,
                           uint32_t elf_flags) {
    DWORD old_protection;
    if (offset > image->size || size > image->size - offset || size == 0 ||
        (offset & 4095u) != 0 || (size & 4095u) != 0) return 0;
    return VirtualProtect(image->base + offset, size,
                          win_elf_protection_for_flags(elf_flags), &old_protection) != 0;
}

int win_elf_image_release(win_elf_image *image) {
    int ok = 1;
    if (image->allocation_base != NULL) {
        ok = VirtualFree(image->allocation_base, 0, MEM_RELEASE) != 0;
    }
    image->base = NULL;
    image->size = 0;
    image->allocation_base = NULL;
    image->allocation_size = 0;
    return ok;
}
