#ifndef WINDOWS_ELF_READER_H
#define WINDOWS_ELF_READER_H

#include "windows_elf_host.h"

#include <stddef.h>
#include <stdint.h>

enum {
    WIN_ELF_EI_MAG0 = 0,
    WIN_ELF_EI_MAG1 = 1,
    WIN_ELF_EI_MAG2 = 2,
    WIN_ELF_EI_MAG3 = 3,
    WIN_ELF_EI_CLASS = 4,
    WIN_ELF_EI_DATA = 5,
    WIN_ELF_CLASS64 = 2,
    WIN_ELF_DATA_LSB = 1,
    WIN_ELF_ET_DYN = 3,
    WIN_ELF_MACHINE_X86_64 = 62,
    WIN_ELF_PT_LOAD = 1,
    WIN_ELF_PAGE_SIZE = 4096
};

typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} win_elf64_ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} win_elf64_phdr;

typedef struct {
    uint64_t min_vaddr;
    uint64_t max_vaddr;
    size_t image_size;
    size_t load_count;
} win_elf64_load_span;

#ifdef __cplusplus
extern "C" {
#endif

int win_elf64_read_header(const win_elf_file *file, win_elf64_ehdr *header);
int win_elf64_read_program_headers(const win_elf_file *file,
                                   const win_elf64_ehdr *header,
                                   win_elf64_phdr **headers,
                                   size_t *header_count);
void win_elf64_free_program_headers(win_elf64_phdr *headers);
int win_elf64_get_load_span(const win_elf64_phdr *headers, size_t header_count,
                            uint64_t file_size, win_elf64_load_span *span);

#ifdef __cplusplus
}
#endif

#endif
