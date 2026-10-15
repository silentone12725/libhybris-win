/*
 * Copyright (C) 2026 The libhybris developers
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "windows_elf_reader.h"

#include <stdio.h>
#include <string.h>

static int fail(const char* message) {
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

static uint64_t page_start(uint64_t value) {
    return value & ~(uint64_t)(WIN_ELF_PAGE_SIZE - 1);
}

static int page_end(uint64_t value, uint64_t* result) {
    if (value > UINT64_MAX - (WIN_ELF_PAGE_SIZE - 1)) return 0;
    *result = page_start(value + WIN_ELF_PAGE_SIZE - 1);
    return 1;
}

int main(int argc, char** argv) {
    win_elf_file file;
    win_elf64_ehdr header;
    win_elf64_phdr* program_headers = NULL;
    size_t program_header_count = 0;
    win_elf64_load_span span;
    win_elf_image image;
    size_t i;

    if (argc != 2) return fail("usage: windows_elf_reader_test <ELF file>");
    if (!win_elf_file_open(argv[1], &file)) return fail("open");
    if (!win_elf64_read_header(&file, &header)) {
        win_elf_file_close(&file);
        return fail("read ELF header");
    }
    if (!win_elf64_read_program_headers(&file, &header, &program_headers,
                                        &program_header_count)) {
        win_elf_file_close(&file);
        return fail("read program headers");
    }
    if (!win_elf64_get_load_span(program_headers, program_header_count, file.size, &span) ||
        span.load_count == 0 || span.image_size == 0 || span.max_vaddr <= span.min_vaddr) {
        win_elf64_free_program_headers(program_headers);
        win_elf_file_close(&file);
        return fail("calculate PT_LOAD span");
    }

    if (!win_elf_image_reserve_aligned(&image, span.image_size, WIN_ELF_PAGE_SIZE)) {
        win_elf64_free_program_headers(program_headers);
        win_elf_file_close(&file);
        return fail("reserve image");
    }
    for (i = 0; i < program_header_count; ++i) {
        const win_elf64_phdr* phdr = &program_headers[i];
        uint64_t segment_offset;
        uint64_t segment_end;
        if (phdr->p_type != WIN_ELF_PT_LOAD) continue;
        if (phdr->p_vaddr < span.min_vaddr ||
            phdr->p_vaddr - span.min_vaddr > SIZE_MAX) {
            win_elf_image_release(&image);
            win_elf64_free_program_headers(program_headers);
            win_elf_file_close(&file);
            return fail("segment offset");
        }
        segment_offset = page_start(phdr->p_vaddr - span.min_vaddr);
        if (!page_end((phdr->p_vaddr - span.min_vaddr) + phdr->p_memsz, &segment_end) ||
            segment_end < segment_offset ||
            !win_elf_image_commit(&image, (size_t)segment_offset,
                                  (size_t)(segment_end - segment_offset)) ||
            phdr->p_filesz > SIZE_MAX ||
            !win_elf_file_read_at(&file, image.base + (size_t)(phdr->p_vaddr - span.min_vaddr),
                                  (size_t)phdr->p_filesz, phdr->p_offset) ||
            !win_elf_image_protect(&image, (size_t)segment_offset,
                                   (size_t)(segment_end - segment_offset), phdr->p_flags)) {
            win_elf_image_release(&image);
            win_elf64_free_program_headers(program_headers);
            win_elf_file_close(&file);
            return fail("load PT_LOAD segment");
        }
    }
    if (!win_elf_image_release(&image)) {
        win_elf64_free_program_headers(program_headers);
        win_elf_file_close(&file);
        return fail("release image");
    }

    printf("PASS: %s\n", argv[1]);
    printf("  size=%llu phnum=%zu loads=%zu span=%llu bytes\n",
           (unsigned long long)file.size, program_header_count, span.load_count,
           (unsigned long long)span.image_size);
    win_elf64_free_program_headers(program_headers);
    win_elf_file_close(&file);
    return 0;
}
