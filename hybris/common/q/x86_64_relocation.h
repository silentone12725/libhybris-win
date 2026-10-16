#ifndef Q_X86_64_RELOCATION_H
#define Q_X86_64_RELOCATION_H

#include <stddef.h>
#include <stdint.h>

/*
 * A freestanding ELF64/x86-64 relocation primitive. The caller owns mapping,
 * symbol/namespace lookup, TLS module registration, and page permissions.
 * image_vaddr is the lowest mapped ELF virtual address; offset is r_offset.
 * A failed operation leaves the image unchanged.
 */
typedef struct {
    uint32_t type;
    uint64_t offset;
    int64_t addend;
} q_x86_64_relocation;

typedef struct {
    uint64_t value;             /* Runtime address, or st_value for STT_TLS. */
    uint64_t tls_module_id;
    uint64_t static_tls_offset; /* Module offset relative to the thread pointer. */
    int has_static_tls;
} q_x86_64_symbol;

/* ELF x86-64 relocation numbers supported by the freestanding primitive. */
enum {
    Q_R_X86_64_NONE = 0,
    Q_R_X86_64_64 = 1,
    Q_R_X86_64_PC32 = 2,
    Q_R_X86_64_GOTPCREL = 9,
    Q_R_X86_64_PLT32 = 4,
    Q_R_X86_64_GLOB_DAT = 6,
    Q_R_X86_64_JUMP_SLOT = 7,
    Q_R_X86_64_RELATIVE = 8,
    Q_R_X86_64_32 = 10,
    Q_R_X86_64_32S = 11,
    Q_R_X86_64_16 = 12,
    Q_R_X86_64_PC16 = 13,
    Q_R_X86_64_8 = 14,
    Q_R_X86_64_PC8 = 15,
    Q_R_X86_64_DTPMOD64 = 16,
    Q_R_X86_64_DTPOFF64 = 17,
    Q_R_X86_64_TPOFF64 = 18,
    Q_R_X86_64_DTPOFF32 = 21,
    Q_R_X86_64_TPOFF32 = 23,
    Q_R_X86_64_PC64 = 24,
    Q_R_X86_64_GOTPCRELX = 41,
    Q_R_X86_64_REX_GOTPCRELX = 42
};

typedef enum {
    Q_RELOC_OK = 0,
    Q_RELOC_OUT_OF_BOUNDS,
    Q_RELOC_OUT_OF_RANGE,
    Q_RELOC_NO_SYMBOL,
    Q_RELOC_NO_STATIC_TLS,
    Q_RELOC_UNSUPPORTED
} q_x86_64_reloc_result;

#ifdef __cplusplus
extern "C" {
#endif

q_x86_64_reloc_result q_x86_64_apply_relocation(
        unsigned char *image, size_t image_size, uint64_t image_vaddr,
        const q_x86_64_relocation *rel, const q_x86_64_symbol *symbol);

#ifdef __cplusplus
}
#endif

#endif
