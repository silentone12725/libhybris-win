#include "x86_64_relocation.h"

#include <limits.h>

static uint64_t addend_modulo(uint64_t value, int64_t addend) {
    if (addend >= 0) {
        return value + (uint64_t)addend;
    }
    return value - ((uint64_t)(-(addend + 1)) + 1);
}

static int fits_signed(uint64_t value, unsigned int bits) {
    uint64_t maximum = (UINT64_C(1) << (bits - 1)) - 1;
    uint64_t minimum = UINT64_MAX - maximum;

    return value <= maximum || value >= minimum;
}

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
        case Q_R_X86_64_NONE:
            return Q_RELOC_OK;
        case Q_R_X86_64_8:
        case Q_R_X86_64_PC8:
            width = 1;
            break;
        case Q_R_X86_64_16:
        case Q_R_X86_64_PC16:
            width = 2;
            break;
        case Q_R_X86_64_PC32:
        case Q_R_X86_64_PLT32:
        case Q_R_X86_64_GOTPCREL:
        case Q_R_X86_64_GOTPCRELX:
        case Q_R_X86_64_REX_GOTPCRELX:
        case Q_R_X86_64_32:
        case Q_R_X86_64_32S:
        case Q_R_X86_64_DTPOFF32:
        case Q_R_X86_64_TPOFF32:
            width = 4;
            break;
        case Q_R_X86_64_64:
        case Q_R_X86_64_PC64:
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
        value = addend_modulo((uint64_t)(uintptr_t)image - image_vaddr,
                              rel->addend);
    } else {
        if (symbol == NULL) return Q_RELOC_NO_SYMBOL;
        switch (rel->type) {
            case Q_R_X86_64_DTPMOD64:
                value = symbol->tls_module_id;
                break;
            case Q_R_X86_64_DTPOFF64:
            case Q_R_X86_64_DTPOFF32:
                value = addend_modulo(symbol->value, rel->addend);
                break;
            case Q_R_X86_64_TPOFF64:
            case Q_R_X86_64_TPOFF32:
                if (!symbol->has_static_tls) return Q_RELOC_NO_STATIC_TLS;
                value = addend_modulo(symbol->static_tls_offset + symbol->value,
                                      rel->addend);
                break;
            default:
                value = addend_modulo(symbol->value, rel->addend);
                break;
        }
    }

    if (rel->type == Q_R_X86_64_PC8 || rel->type == Q_R_X86_64_PC16 ||
         rel->type == Q_R_X86_64_PC32 || rel->type == Q_R_X86_64_PLT32 ||
         rel->type == Q_R_X86_64_GOTPCREL ||
         rel->type == Q_R_X86_64_GOTPCRELX ||
         rel->type == Q_R_X86_64_REX_GOTPCRELX ||
         rel->type == Q_R_X86_64_PC64) {
        value -= place;
        if ((rel->type == Q_R_X86_64_PC8 && !fits_signed(value, 8)) ||
            (rel->type == Q_R_X86_64_PC16 && !fits_signed(value, 16)) ||
            ((rel->type == Q_R_X86_64_PC32 ||
              rel->type == Q_R_X86_64_PLT32 ||
              rel->type == Q_R_X86_64_GOTPCREL ||
              rel->type == Q_R_X86_64_GOTPCRELX ||
              rel->type == Q_R_X86_64_REX_GOTPCRELX) && !fits_signed(value, 32))) {
            return Q_RELOC_OUT_OF_RANGE;
        }
    } else if (rel->type == Q_R_X86_64_32 && value > UINT32_MAX) {
        return Q_RELOC_OUT_OF_RANGE;
    } else if ((rel->type == Q_R_X86_64_32S ||
                rel->type == Q_R_X86_64_TPOFF32) &&
               !fits_signed(value, 32)) {
        return Q_RELOC_OUT_OF_RANGE;
    } else if (rel->type == Q_R_X86_64_16 && value > UINT16_MAX) {
        return Q_RELOC_OUT_OF_RANGE;
    } else if (rel->type == Q_R_X86_64_8 && value > UINT8_MAX) {
        return Q_RELOC_OUT_OF_RANGE;
    } else if (rel->type == Q_R_X86_64_DTPOFF32 && value > UINT32_MAX) {
        return Q_RELOC_OUT_OF_RANGE;
    }

    /* ELF64/x86-64 is little-endian. Byte writes also permit unaligned slots. */
    for (index = 0; index < width; ++index) {
        target[index] = (unsigned char)(value >> (8 * index));
    }
    return Q_RELOC_OK;
}
