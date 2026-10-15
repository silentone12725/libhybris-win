#include "x86_64_relocation.h"

#include <limits.h>

/* ELF x86-64 relocation numbers, kept local so a Windows build needs no elf.h. */
enum {
    Q_R_X86_64_64 = 1,
    Q_R_X86_64_PC32 = 2,
    Q_R_X86_64_GLOB_DAT = 6,
    Q_R_X86_64_JUMP_SLOT = 7,
    Q_R_X86_64_RELATIVE = 8,
    Q_R_X86_64_32 = 10,
    Q_R_X86_64_32S = 11,
    Q_R_X86_64_DTPMOD64 = 16,
    Q_R_X86_64_DTPOFF64 = 17,
    Q_R_X86_64_TPOFF64 = 18
};

q_x86_64_reloc_result q_x86_64_apply_relocation(
        unsigned char *image, size_t image_size, uint64_t image_vaddr,
        const q_x86_64_relocation *rel, const q_x86_64_symbol *symbol) {
    size_t width;
    uint64_t value;
    uint64_t place;
    size_t index;
    unsigned char *target;

    if (image == NULL || rel == NULL) return Q_RELOC_OUT_OF_BOUNDS;

    switch (rel->type) {
        case Q_R_X86_64_PC32:
        case Q_R_X86_64_32:
        case Q_R_X86_64_32S:
            width = 4;
            break;
        case Q_R_X86_64_64:
        case Q_R_X86_64_GLOB_DAT:
        case Q_R_X86_64_JUMP_SLOT:
        case Q_R_X86_64_RELATIVE:
        case Q_R_X86_64_DTPMOD64:
        case Q_R_X86_64_DTPOFF64:
        case Q_R_X86_64_TPOFF64:
            width = 8;
            break;
        default:
            return Q_RELOC_UNSUPPORTED;
    }

    if (rel->offset < image_vaddr || rel->offset - image_vaddr > image_size ||
        width > image_size - (size_t)(rel->offset - image_vaddr)) {
        return Q_RELOC_OUT_OF_BOUNDS;
    }
    target = image + (size_t)(rel->offset - image_vaddr);
    place = (uint64_t)(uintptr_t)target;

    if (rel->type == Q_R_X86_64_RELATIVE) {
        value = (uint64_t)(uintptr_t)image - image_vaddr + (uint64_t)rel->addend;
    } else {
        if (symbol == NULL) return Q_RELOC_NO_SYMBOL;
        switch (rel->type) {
            case Q_R_X86_64_DTPMOD64:
                value = symbol->tls_module_id;
                break;
            case Q_R_X86_64_DTPOFF64:
                value = symbol->value + (uint64_t)rel->addend;
                break;
            case Q_R_X86_64_TPOFF64:
                if (!symbol->has_static_tls) return Q_RELOC_NO_STATIC_TLS;
                value = symbol->static_tls_offset + symbol->value +
                        (uint64_t)rel->addend;
                break;
            default:
                value = symbol->value + (uint64_t)rel->addend;
                break;
        }
    }

    if (rel->type == Q_R_X86_64_PC32) {
        value -= place;
        if (value > INT32_MAX && value < UINT64_MAX - (uint64_t)INT32_MAX) {
            return Q_RELOC_OUT_OF_RANGE;
        }
    } else if (rel->type == Q_R_X86_64_32 && value > UINT32_MAX) {
        return Q_RELOC_OUT_OF_RANGE;
    } else if (rel->type == Q_R_X86_64_32S && value > INT32_MAX &&
               value < UINT64_MAX - (uint64_t)INT32_MAX) {
        return Q_RELOC_OUT_OF_RANGE;
    }

    /* ELF64/x86-64 is little-endian. Byte writes also permit unaligned slots. */
    for (index = 0; index < width; ++index) {
        target[index] = (unsigned char)(value >> (8 * index));
    }
    return Q_RELOC_OK;
}
