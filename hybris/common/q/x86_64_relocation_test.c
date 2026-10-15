#include "x86_64_relocation.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    R_NONE = 0,
    R_64 = 1,
    R_PC32 = 2,
    R_PLT32 = 4,
    R_GLOB_DAT = 6,
    R_RELATIVE = 8,
    R_32 = 10,
    R_32S = 11,
    R_16 = 12,
    R_PC16 = 13,
    R_8 = 14,
    R_PC8 = 15,
    R_DTPMOD64 = 16,
    R_DTPOFF64 = 17,
    R_TPOFF64 = 18,
    R_DTPOFF32 = 21,
    R_TPOFF32 = 23,
    R_PC64 = 24,
    R_GOTPCREL = 9
};

static int failures;

static void expect(const char *name, int condition) {
    printf("%s: %s\n", name, condition ? "PASS" : "FAIL");
    if (!condition) ++failures;
}

static uint64_t read_u64(const unsigned char *p) {
    uint64_t result = 0;
    size_t i;
    for (i = 0; i < 8; ++i) result |= (uint64_t)p[i] << (8 * i);
    return result;
}

static uint32_t read_u32(const unsigned char *p) {
    uint32_t result = 0;
    size_t i;
    for (i = 0; i < 4; ++i) result |= (uint32_t)p[i] << (8 * i);
    return result;
}

static uint16_t read_u16(const unsigned char *p) {
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

int main(void) {
    unsigned char image[128];
    unsigned char before[128];
    const uint64_t vaddr = 0x400000;
    q_x86_64_relocation rel;
    q_x86_64_symbol symbol;
    q_x86_64_reloc_result result;

    memset(image, 0, sizeof(image));
    memset(&symbol, 0, sizeof(symbol));
    symbol.value = 0x123456789abcdef0ULL;

    rel = (q_x86_64_relocation){R_64, vaddr + 1, 0x10};
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("absolute 64-bit relocation", result == Q_RELOC_OK &&
           read_u64(image + 1) == 0x123456789abcdf00ULL);

    rel = (q_x86_64_relocation){R_GLOB_DAT, vaddr + 9, -0x10};
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("GLOB_DAT addend", result == Q_RELOC_OK &&
           read_u64(image + 9) == 0x123456789abcdee0ULL);

    rel = (q_x86_64_relocation){R_RELATIVE, vaddr + 17, 0x20};
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, NULL);
    expect("RELATIVE without symbol", result == Q_RELOC_OK &&
           read_u64(image + 17) == (uint64_t)(uintptr_t)image - vaddr + 0x20);

    rel = (q_x86_64_relocation){R_32, vaddr + 25, 0};
    symbol.value = 0x00000000fedcba98ULL;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("checked 32-bit relocation", result == Q_RELOC_OK &&
           read_u32(image + 25) == 0xfedcba98U);

    rel = (q_x86_64_relocation){R_PC32, vaddr + 29, 0};
    symbol.value = (uint64_t)(uintptr_t)(image + 29) + 0x100;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("PC-relative relocation", result == Q_RELOC_OK && read_u32(image + 29) == 0x100);

    symbol.tls_module_id = 7;
    symbol.value = 0x30;
    symbol.static_tls_offset = 0x200;
    symbol.has_static_tls = 1;
    rel = (q_x86_64_relocation){R_DTPMOD64, vaddr + 37, 0};
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("TLS module id", result == Q_RELOC_OK && read_u64(image + 37) == 7);
    rel = (q_x86_64_relocation){R_DTPOFF64, vaddr + 45, 4};
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("TLS dynamic offset", result == Q_RELOC_OK && read_u64(image + 45) == 0x34);
    rel = (q_x86_64_relocation){R_TPOFF64, vaddr + 53, 0};
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("TLS static offset", result == Q_RELOC_OK && read_u64(image + 53) == 0x230);

    rel = (q_x86_64_relocation){R_16, vaddr + 61, 0x10};
    symbol.value = 0xabcd;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("absolute 16-bit relocation", result == Q_RELOC_OK &&
           read_u16(image + 61) == 0xabdd);

    rel = (q_x86_64_relocation){R_8, vaddr + 63, 0x0f};
    symbol.value = 0xf0;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("absolute 8-bit relocation", result == Q_RELOC_OK && image[63] == 0xff);

    rel = (q_x86_64_relocation){R_PC16, vaddr + 64, 0};
    symbol.value = (uint64_t)(uintptr_t)(image + 64) + 0x100;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("PC-relative 16-bit relocation", result == Q_RELOC_OK &&
           read_u16(image + 64) == 0x100);

    rel = (q_x86_64_relocation){R_PC8, vaddr + 66, 0};
    symbol.value = (uint64_t)(uintptr_t)(image + 66) - 0x20;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("PC-relative 8-bit relocation", result == Q_RELOC_OK && image[66] == 0xe0);

    rel = (q_x86_64_relocation){R_PC64, vaddr + 68, 0x10};
    symbol.value = (uint64_t)(uintptr_t)(image + 68) + 0x1000;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("PC-relative 64-bit relocation", result == Q_RELOC_OK &&
           read_u64(image + 68) == 0x1010);

    rel = (q_x86_64_relocation){R_PLT32, vaddr + 76, 0};
    symbol.value = (uint64_t)(uintptr_t)(image + 76) - 0x80;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("PLT32 relocation", result == Q_RELOC_OK && read_u32(image + 76) == 0xffffff80U);

    rel = (q_x86_64_relocation){R_DTPOFF32, vaddr + 80, 0x20};
    symbol.value = 0x100;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("TLS dynamic 32-bit offset", result == Q_RELOC_OK &&
           read_u32(image + 80) == 0x120);

    rel = (q_x86_64_relocation){R_TPOFF32, vaddr + 84, 0};
    symbol.value = 0x30;
    symbol.static_tls_offset = (uint64_t)-0x200;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("TLS static 32-bit offset", result == Q_RELOC_OK &&
           read_u32(image + 84) == (uint32_t)-0x1d0);

    rel = (q_x86_64_relocation){R_32S, vaddr + 88, 1};
    symbol.value = (uint64_t)-2;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("signed 32-bit relocation", result == Q_RELOC_OK &&
           read_u32(image + 88) == 0xffffffffU);

    rel = (q_x86_64_relocation){R_NONE, vaddr + sizeof(image) + 1, 0};
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, NULL);
    expect("NONE relocation", result == Q_RELOC_OK);

    memcpy(before, image, sizeof(image));
    rel = (q_x86_64_relocation){R_TPOFF64, vaddr + 1, 0};
    symbol.has_static_tls = 0;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("TLS static requirement", result == Q_RELOC_NO_STATIC_TLS &&
           memcmp(before, image, sizeof(image)) == 0);

    memcpy(before, image, sizeof(image));
    rel = (q_x86_64_relocation){R_16, vaddr + 92, 0};
    symbol.value = 0x10000;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("16-bit overflow", result == Q_RELOC_OUT_OF_RANGE &&
           memcmp(before, image, sizeof(image)) == 0);

    memcpy(before, image, sizeof(image));
    rel = (q_x86_64_relocation){R_PC16, vaddr + 94, 0};
    symbol.value = (uint64_t)(uintptr_t)(image + 94) + 0x10000;
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("PC-relative 16-bit overflow", result == Q_RELOC_OUT_OF_RANGE &&
           memcmp(before, image, sizeof(image)) == 0);

    rel = (q_x86_64_relocation){R_64, vaddr + 124, 0};
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("bounds check", result == Q_RELOC_OUT_OF_BOUNDS);
    rel = (q_x86_64_relocation){R_GOTPCREL, vaddr, 0};
    result = q_x86_64_apply_relocation(image, sizeof(image), vaddr, &rel, &symbol);
    expect("GOT relocation unsupported", result == Q_RELOC_UNSUPPORTED);

    printf("RESULT: %s failures=%d\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
