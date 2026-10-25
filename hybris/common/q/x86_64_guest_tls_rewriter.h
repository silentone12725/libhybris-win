/* SPDX-License-Identifier: BSD-3-Clause */
#pragma once

#include <stddef.h>

#include "windows_elf_defs.h"

#if defined(_WIN32) && defined(__x86_64__)
bool rewrite_x86_64_guest_tls(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                              ElfW(Addr) load_bias, size_t module_id,
                              const char* realpath);
#endif
