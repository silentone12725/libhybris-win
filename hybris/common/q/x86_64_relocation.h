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
