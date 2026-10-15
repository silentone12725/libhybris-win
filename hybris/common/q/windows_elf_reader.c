#include "windows_elf_reader.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(sizeof(win_elf64_ehdr) == 64, "unexpected ELF64 header layout");
_Static_assert(sizeof(win_elf64_phdr) == 56, "unexpected ELF64 phdr layout");

static int checked_add_u64(uint64_t first, uint64_t second, uint64_t *result) {
    if (UINT64_MAX - first < second) return 0;
    *result = first + second;
    return 1;
}

static int checked_mul_u64(uint64_t first, uint64_t second, uint64_t *result) {
    if (first != 0 && second > UINT64_MAX / first) return 0;
    *result = first * second;
    return 1;
}

static uint64_t page_start(uint64_t value) {
    return value & ~(uint64_t)(WIN_ELF_PAGE_SIZE - 1);
}

static int page_end(uint64_t value, uint64_t *result) {
    uint64_t rounded;
    if (!checked_add_u64(value, WIN_ELF_PAGE_SIZE - 1, &rounded)) return 0;
    *result = page_start(rounded);
    return 1;
}

static int is_power_of_two(uint64_t value) {
    return value == 0 || (value & (value - 1)) == 0;
}

static int valid_header(const win_elf64_ehdr *header) {
    return header->e_ident[WIN_ELF_EI_MAG0] == 0x7f &&
           header->e_ident[WIN_ELF_EI_MAG1] == 'E' &&
           header->e_ident[WIN_ELF_EI_MAG2] == 'L' &&
           header->e_ident[WIN_ELF_EI_MAG3] == 'F' &&
           header->e_ident[WIN_ELF_EI_CLASS] == WIN_ELF_CLASS64 &&
           header->e_ident[WIN_ELF_EI_DATA] == WIN_ELF_DATA_LSB &&
           header->e_type == WIN_ELF_ET_DYN &&
           header->e_machine == WIN_ELF_MACHINE_X86_64 &&
           header->e_ehsize == sizeof(win_elf64_ehdr) &&
           header->e_phentsize == sizeof(win_elf64_phdr) &&
           header->e_phnum != 0;
}

int win_elf64_read_header(const win_elf_file *file, win_elf64_ehdr *header) {
    if (file == NULL || header == NULL || file->size < sizeof(*header)) return 0;
    if (!win_elf_file_read_at(file, header, sizeof(*header), 0)) return 0;
    return valid_header(header);
}

int win_elf64_read_program_headers(const win_elf_file *file,
                                   const win_elf64_ehdr *header,
                                   win_elf64_phdr **headers,
                                   size_t *header_count) {
    uint64_t table_size;
    uint64_t table_end;
    win_elf64_phdr *table;

    if (headers != NULL) *headers = NULL;
    if (header_count != NULL) *header_count = 0;
    if (headers == NULL || header_count == NULL || file == NULL || header == NULL ||
        !valid_header(header) ||
        !checked_mul_u64(header->e_phnum, header->e_phentsize, &table_size) ||
        !checked_add_u64(header->e_phoff, table_size, &table_end) ||
        table_end > file->size || table_size > SIZE_MAX || table_size > UINT32_MAX) {
        return 0;
    }

    table = (win_elf64_phdr *)malloc((size_t)table_size);
    if (table == NULL || !win_elf_file_read_at(file, table, (size_t)table_size,
                                                header->e_phoff)) {
        free(table);
        return 0;
    }
    *headers = table;
    *header_count = header->e_phnum;
    return 1;
}

void win_elf64_free_program_headers(win_elf64_phdr *headers) {
    free(headers);
}

int win_elf64_get_load_span(const win_elf64_phdr *headers, size_t header_count,
                            uint64_t file_size, win_elf64_load_span *span) {
    uint64_t min_vaddr = UINT64_MAX;
    uint64_t max_vaddr = 0;
    uint64_t aligned_min;
    uint64_t aligned_max;
    size_t load_count = 0;
    size_t i;

    if (headers == NULL || span == NULL) return 0;
    for (i = 0; i < header_count; ++i) {
        const win_elf64_phdr *header = &headers[i];
        uint64_t file_end;
        uint64_t memory_end;

        if (header->p_type != WIN_ELF_PT_LOAD) continue;
        ++load_count;
        if (header->p_filesz > header->p_memsz ||
            !checked_add_u64(header->p_offset, header->p_filesz, &file_end) ||
            file_end > file_size ||
            !checked_add_u64(header->p_vaddr, header->p_memsz, &memory_end) ||
            !is_power_of_two(header->p_align)) {
            return 0;
        }
        if (header->p_vaddr < min_vaddr) min_vaddr = header->p_vaddr;
        if (memory_end > max_vaddr) max_vaddr = memory_end;
    }
    if (load_count == 0 || min_vaddr == UINT64_MAX ||
        !page_end(max_vaddr, &aligned_max)) {
        return 0;
    }
    aligned_min = page_start(min_vaddr);
    if (aligned_max <= aligned_min || aligned_max - aligned_min > SIZE_MAX) return 0;

    span->min_vaddr = aligned_min;
    span->max_vaddr = aligned_max;
    span->image_size = (size_t)(aligned_max - aligned_min);
    span->load_count = load_count;
    return 1;
}
