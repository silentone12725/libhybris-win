#ifndef HYBRIS_WINDOWS_ELF_H
#define HYBRIS_WINDOWS_ELF_H

#if defined(_WIN32)

#include "../../../windows_elf_defs.h"

typedef Elf64_auxv_t Elf_auxv_t;

#else

#include_next <elf.h>

#endif

#endif
