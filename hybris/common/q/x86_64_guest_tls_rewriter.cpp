/* SPDX-License-Identifier: BSD-3-Clause */
#include "x86_64_guest_tls_rewriter.h"

#if defined(_WIN32) && defined(__x86_64__)

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <vector>

#ifndef SHF_EXECINSTR
#define SHF_EXECINSTR 0x4u
#endif

#include "linker_globals.h"
#include "linker_tls.h"

namespace {

using Byte = unsigned char;

struct Access {
  enum class MemoryOp { Move, And, Add, X87Da };
  size_t length;
  unsigned reg;
  unsigned base_reg;
  bool load;
  bool wide;
  bool address_only;
  bool base_relative;
  bool tp_relative;
  int64_t tpoff;
  MemoryOp op;
  unsigned op_reg;
};

static bool decode(const Byte* p, Access* out) {
  size_t i = 0;
  if (p[i++] != 0x64) return false;
  Byte rex = 0;
  if ((p[i] & 0xf0) == 0x40) rex = p[i++];
  const Byte opcode = p[i++];
  if (opcode != 0x8b && opcode != 0x89 && opcode != 0x23 && opcode != 0x03)
    return false;
  const Byte modrm = p[i++];
  const unsigned mod = modrm >> 6;
  unsigned base_reg = modrm & 7;
  int32_t displacement = 0;
  bool absolute = false;
  if ((modrm & 7) == 4) {
    const Byte sib = p[i++];
    if ((sib >> 6) != 0 || ((sib >> 3) & 7) != 4) return false;
    if ((sib & 7) == 5 && mod == 0) {
      absolute = true;
    } else {
      base_reg = (sib & 7) | ((rex & 1) != 0 ? 8 : 0);
    }
  } else if (mod == 0 && (modrm & 7) == 5) {
    return false;
  }
  if (absolute) {
    std::memcpy(&displacement, p + i, sizeof(displacement));
    i += sizeof(displacement);
  } else if (mod == 0) {
    displacement = 0;
  } else if (mod == 1) {
    const int8_t value = static_cast<int8_t>(p[i++]);
    displacement = value;
  } else if (mod == 2) {
    std::memcpy(&displacement, p + i, sizeof(displacement));
    i += sizeof(displacement);
  } else {
    return false;
  }
  out->length = i;
  out->reg = ((modrm >> 3) & 7) | ((rex & 4) != 0 ? 8 : 0);
  out->base_reg = base_reg;
  // 0x23 is a read-modify-write form (AND r32, r/m32), while 0x03 is the
  // corresponding ADD r64, r/m64 form used by Android initial-exec TLS.
  // Both still leave the destination register as the result of the access,
  // but unlike MOV they also produce arithmetic flags that the relocated
  // instruction must preserve.
  out->load = opcode == 0x8b || opcode == 0x23 || opcode == 0x03;
  out->wide = (rex & 8) != 0;
  out->address_only = false;
  out->base_relative = !absolute;
  out->tp_relative = absolute;
  out->tpoff = displacement;
  out->op = opcode == 0x23 ? Access::MemoryOp::And :
            (opcode == 0x03 ? Access::MemoryOp::Add :
             (opcode == 0xda ? Access::MemoryOp::X87Da : Access::MemoryOp::Move));
  out->op_reg = (modrm >> 3) & 7;
  return true;
}

void emit(std::vector<Byte>* code, Byte value) { code->push_back(value); }
void emit64(std::vector<Byte>* code, uint64_t value) {
  for (unsigned i = 0; i < 8; ++i) emit(code, static_cast<Byte>(value >> (i * 8)));
}
void emit32(std::vector<Byte>* code, uint32_t value) {
  for (unsigned i = 0; i < 4; ++i) emit(code, static_cast<Byte>(value >> (i * 8)));
}
void mov_imm64(std::vector<Byte>* code, unsigned reg, uint64_t value) {
  emit(code, static_cast<Byte>(0x48 | ((reg >> 3) & 1)));
  emit(code, static_cast<Byte>(0xb8 | (reg & 7)));
  emit64(code, value);
}

void call_with_dynamic_stack_alignment(std::vector<Byte>* code) {
  // The replacement may run at any point in a guest function, so its current
  // RSP parity is not derivable from the function prologue alone.  Align the
  // SysV helper call at runtime and restore the exact incoming RSP afterward.
  emit(code, 0x48); emit(code, 0xf7); emit(code, 0xc4); emit(code, 0x08);
  emit(code, 0x00); emit(code, 0x00); emit(code, 0x00);  // test rsp, 8
  emit(code, 0x74); emit(code, 0x0d);                   // jz no_adjust
  emit(code, 0x48); emit(code, 0x83); emit(code, 0xec); emit(code, 0x08);
  emit(code, 0x41); emit(code, 0xff); emit(code, 0xd3);  // call r11
  emit(code, 0x48); emit(code, 0x83); emit(code, 0xc4); emit(code, 0x08);
  emit(code, 0xeb); emit(code, 0x03);                   // jmp after_no_adjust
  emit(code, 0x41); emit(code, 0xff); emit(code, 0xd3);  // no_adjust: call r11
}

void mov_reg_reg(std::vector<Byte>* code, unsigned dst, unsigned src) {
  emit(code, static_cast<Byte>(0x48 | (src >= 8 ? 4 : 0) | (dst >= 8 ? 1 : 0)));
  emit(code, 0x89);
  emit(code, static_cast<Byte>(0xc0 | ((src & 7) << 3) | (dst & 7)));
}

void add_reg_reg(std::vector<Byte>* code, unsigned dst, unsigned src) {
  emit(code, static_cast<Byte>(0x48 | (src >= 8 ? 4 : 0) | (dst >= 8 ? 1 : 0)));
  emit(code, 0x01);
  emit(code, static_cast<Byte>(0xc0 | ((src & 7) << 3) | (dst & 7)));
}

void add_imm32(std::vector<Byte>* code, unsigned reg, int32_t value) {
  emit(code, static_cast<Byte>(0x48 | (reg >= 8 ? 1 : 0)));
  emit(code, 0x81);
  emit(code, static_cast<Byte>(0xc0 | (reg & 7)));
  emit32(code, static_cast<uint32_t>(value));
}

void mov_memory_reg(std::vector<Byte>* code, unsigned base, unsigned src, bool wide) {
  emit(code, static_cast<Byte>(0x40 | (wide ? 8 : 0) | (src >= 8 ? 4 : 0) |
                                     (base >= 8 ? 1 : 0)));
  emit(code, 0x89);
  emit(code, static_cast<Byte>(((src & 7) << 3) | (base & 7)));
  if ((base & 7) == 4) emit(code, 0x24);
}

void mov_reg_memory(std::vector<Byte>* code, unsigned dst, unsigned base, bool wide) {
  emit(code, static_cast<Byte>(0x40 | (wide ? 8 : 0) | (dst >= 8 ? 4 : 0) |
                                     (base >= 8 ? 1 : 0)));
  emit(code, 0x8b);
  emit(code, static_cast<Byte>(((dst & 7) << 3) | (base & 7)));
  if ((base & 7) == 4) emit(code, 0x24);
}

void and_reg_memory(std::vector<Byte>* code, unsigned dst, unsigned base, bool wide) {
  emit(code, static_cast<Byte>(0x40 | (wide ? 8 : 0) | (dst >= 8 ? 4 : 0) |
                                     (base >= 8 ? 1 : 0)));
  emit(code, 0x23);
  emit(code, static_cast<Byte>(0xc0 | ((dst & 7) << 3) | (base & 7)));
  if ((base & 7) == 4) emit(code, 0x24);
}

void add_reg_memory(std::vector<Byte>* code, unsigned dst, unsigned base, bool wide) {
  emit(code, static_cast<Byte>(0x40 | (wide ? 8 : 0) | (dst >= 8 ? 4 : 0) |
                                     (base >= 8 ? 1 : 0)));
  emit(code, 0x03);
  emit(code, static_cast<Byte>(0xc0 | ((dst & 7) << 3) | (base & 7)));
  if ((base & 7) == 4) emit(code, 0x24);
}

void x87_da_memory(std::vector<Byte>* code, unsigned op_reg, unsigned base) {
  emit(code, static_cast<Byte>(0x40 | (base >= 8 ? 1 : 0)));
  emit(code, 0xda);
  emit(code, static_cast<Byte>(((op_reg & 7) << 3) | (base & 7)));
  if ((base & 7) == 4) emit(code, 0x24);
}

void mov_stack_disp_reg(std::vector<Byte>* code, unsigned src, int32_t displacement) {
  // mov [rsp+disp32], src; the saved initial flags word is below the saved
  // registers and any temporary alignment word.
  emit(code, static_cast<Byte>(0x48 | (src >= 8 ? 4 : 0)));
  emit(code, 0x89);
  emit(code, static_cast<Byte>(0x80 | ((src & 7) << 3) | 4));
  emit(code, 0x24);
  emit32(code, static_cast<uint32_t>(displacement));
}

void push_reg(std::vector<Byte>* code, unsigned reg) {
  if (reg >= 8) emit(code, 0x41);
  emit(code, static_cast<Byte>(0x50 | (reg & 7)));
}

void pop_reg(std::vector<Byte>* code, unsigned reg) {
  if (reg >= 8) emit(code, 0x41);
  emit(code, static_cast<Byte>(0x58 | (reg & 7)));
}

size_t instruction_length(const Byte* p) {
  size_t i = 0;
  while (p[i] == 0x64 || p[i] == 0x65 || p[i] == 0x66 || p[i] == 0x67 ||
         p[i] == 0xf0 || p[i] == 0xf2 || p[i] == 0xf3) ++i;
  const bool rex_w = (p[i] & 0xf0) == 0x40 && (p[i] & 8) != 0;
  if ((p[i] & 0xf0) == 0x40) ++i;
  const Byte opcode = p[i++];
  if (opcode == 0x0f) {
    const Byte extended = p[i++];
    if (extended >= 0x80 && extended <= 0x8f) return i + 4;  // jcc rel32
    // 3-byte opcode groups (SSSE3, SSE4): conservative fallback.
    if (extended == 0x38 || extended == 0x3a) return 0;
    // setcc, cmovcc and most SSE opcodes all have a ModRM byte.
    const Byte modrm2 = p[i++];
    const unsigned mod2 = modrm2 >> 6;
    if (mod2 != 3 && (modrm2 & 7) == 4) {
      const Byte sib2 = p[i++];
      if (mod2 == 0 && (sib2 & 7) == 5) i += 4;
    }
    if (mod2 == 0 && (modrm2 & 7) == 5) i += 4;
    if (mod2 == 1) ++i;
    if (mod2 == 2) i += 4;
    // Opcodes that carry an imm8 after ModRM.
    switch (extended) {
      case 0x70: case 0x71: case 0x72: case 0x73:
      case 0xc2: case 0xc4: case 0xc5: case 0xc6:
      case 0xa4: case 0xac:
        ++i;
        break;
    }
    return i;
  }
  if (opcode == 0xe8 || opcode == 0xe9 || opcode == 0x68) return i + 4;
  if (opcode == 0xeb || (opcode >= 0x70 && opcode <= 0x7f) ||
      (opcode >= 0xe0 && opcode <= 0xe3) || opcode == 0x6a) return i + 1;
  if (opcode >= 0xb0 && opcode <= 0xb7) return i + 1;
  if (opcode >= 0xb8 && opcode <= 0xbf) return i + (rex_w ? 8 : 4);
  bool has_modrm = false;
  size_t immediate = 0;
  switch (opcode) {
    // Accumulator-register short forms with imm32
    case 0x05: case 0x0d: case 0x15: case 0x1d: case 0x2d: case 0x35: case 0x3d:
      return i + 4;
    // Accumulator-register short forms with imm8
    case 0x04: case 0x0c: case 0x14: case 0x1c: case 0x24: case 0x2c: case 0x34: case 0x3c:
      return i + 1;
    case 0x00: case 0x01: case 0x02: case 0x03:
    case 0x08: case 0x09: case 0x0a: case 0x0b:
    case 0x10: case 0x11: case 0x12: case 0x13:
    case 0x18: case 0x19: case 0x1a: case 0x1b:
    case 0x20: case 0x21: case 0x22: case 0x23:
    case 0x28: case 0x29: case 0x2a: case 0x2b:
    case 0x30: case 0x31: case 0x32: case 0x33:
    case 0x38: case 0x39: case 0x3a: case 0x3b:
    case 0x63: case 0x8b: case 0x89: case 0x8d: case 0x85: case 0xfe: case 0xff:
       has_modrm = true;
       break;
    case 0x80: case 0x81: case 0xc6: case 0xc7:
      has_modrm = true;
      immediate = opcode == 0x80 ? 1 : 4;
      break;
    case 0xa9:
      return i + 4;
    case 0x25:
      return i + 4;
    case 0x83: case 0xc1: case 0xf6:
      has_modrm = true;
      immediate = 1;
      break;
    case 0x6c: case 0x6d: case 0x6e: case 0x6f: case 0x99: case 0xc9: case 0xec: case 0xf1:
    case 0x90: case 0xa4: case 0xa5: case 0xa6: case 0xa7:
    case 0xaa: case 0xab: case 0xac: case 0xad: case 0xae: case 0xaf:
    case 0xc3: case 0xcc: case 0x5d:
      return i;
    case 0xd4: case 0xd5:
      return i + 1;
    case 0x9a:
      return i + 6;
    default:
      if (opcode >= 0x50 && opcode <= 0x5f) return i;
      return 0;
  }
  const Byte modrm = p[i++];
  const unsigned mod = modrm >> 6;
  if (mod != 3 && (modrm & 7) == 4) {
    const Byte sib = p[i++];
    if (mod == 0 && (sib & 7) == 5) i += 4;
  }
  if (mod == 0 && (modrm & 7) == 5) i += 4;
  if (mod == 1) ++i;
  if (mod == 2) i += 4;
  return i + immediate;
}

size_t ignored_fs_prefix_length(const Byte* p) {
  if (p[0] != 0x64) return 0;
  size_t i = 1;
  if ((p[i] & 0xf0) == 0x40) ++i;
  const Byte opcode = p[i++];
  const bool has_modrm =
      opcode == 0x00 || opcode == 0x01 || opcode == 0x02 || opcode == 0x03 ||
      opcode == 0x08 || opcode == 0x09 || opcode == 0x0a || opcode == 0x0b ||
      opcode == 0x10 || opcode == 0x11 || opcode == 0x12 || opcode == 0x13 ||
      opcode == 0x18 || opcode == 0x19 || opcode == 0x1a || opcode == 0x1b ||
      opcode == 0x20 || opcode == 0x21 || opcode == 0x22 || opcode == 0x23 ||
      opcode == 0x28 || opcode == 0x29 || opcode == 0x2a || opcode == 0x2b ||
      opcode == 0x30 || opcode == 0x31 || opcode == 0x32 || opcode == 0x33 ||
      opcode == 0x38 || opcode == 0x39 || opcode == 0x3a || opcode == 0x3b ||
      opcode == 0x81 || opcode == 0x83 || opcode == 0x85 || opcode == 0x8b ||
      opcode == 0x89 || opcode == 0x8d || opcode == 0xc1 || opcode == 0xc7 ||
      opcode == 0xfe || opcode == 0xff;
  if (opcode == 0x90 || opcode == 0xc3 || opcode == 0xe8 || opcode == 0xe9 ||
      opcode == 0xeb || (opcode >= 0x70 && opcode <= 0x7f) ||
      (opcode >= 0xe0 && opcode <= 0xe3) || opcode == 0x24 ||
      (opcode >= 0x6c && opcode <= 0x6f) || (opcode >= 0xa4 && opcode <= 0xa7) ||
      (opcode >= 0xaa && opcode <= 0xaf)) {
    const size_t length = instruction_length(p + 1);
    return length == 0 ? 0 : length + 1;
  }
  if (!has_modrm) return 0;
  if ((p[i] >> 6) != 3) return 0;
  const size_t length = instruction_length(p + 1);
  return length == 0 ? 0 : length + 1;
}

const unsigned kSavedRegs[] = {0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

struct StubPage {
  Byte* base;
  size_t used;
};

std::vector<StubPage> g_stub_pages;

std::vector<Byte> make_stub(uintptr_t return_address, size_t module_id, const Access& access,
                            const Byte* relocated, size_t relocated_size) {
  std::vector<Byte> code;
  emit(&code, 0x9c);  // pushfq
  for (unsigned reg : kSavedRegs) {
    if ((access.load || access.address_only) && reg == access.reg) continue;
    push_reg(&code, reg);
  }
  if (access.base_relative) push_reg(&code, access.base_reg);
  const size_t saved_count = sizeof(kSavedRegs) / sizeof(kSavedRegs[0]) -
      ((access.load || access.address_only) ? 1 : 0) +
      (access.base_relative ? 1 : 0);
  // SysV guest functions reach ordinary TLS accesses with RSP 16-byte aligned
  // after their prologue.  Add one word when the saved-register pushes leave
  // the stack at the wrong parity before the helper call.
  const bool align_stack = (1 + saved_count) % 2 == 0;
  if (align_stack) {
    emit(&code, 0x48); emit(&code, 0x83); emit(&code, 0xec); emit(&code, 8);
  }

  const uintptr_t resolver = access.base_relative || access.tp_relative || access.tpoff == 0
      ? reinterpret_cast<uintptr_t>(&linker_tls_guest_thread_pointer)
      : reinterpret_cast<uintptr_t>(&linker_tls_guest_addr);
  if (!access.base_relative && !access.tp_relative && access.tpoff != 0) {
    mov_imm64(&code, 7, module_id);  // SysV first argument: rdi
    mov_imm64(&code, 6, static_cast<uint64_t>(static_cast<int64_t>(access.tpoff)));
  }
  const unsigned store_value_reg = access.reg == 12 ? 13 : 12;
  if (!access.load && !access.address_only && access.op != Access::MemoryOp::X87Da) {
    // r12/r13 are callee-saved in the SysV guest ABI, so they survive the
    // resolver call while the original source register may be call-clobbered.
    mov_reg_reg(&code, store_value_reg, access.reg);
  }
  mov_imm64(&code, 11, resolver);
  call_with_dynamic_stack_alignment(&code);

  if (access.tp_relative && !access.base_relative) {
    emit(&code, 0x48); emit(&code, 0x8d); emit(&code, 0x80);
    emit32(&code, static_cast<uint32_t>(access.tpoff));
  } else if (access.base_relative) {
    const unsigned address_reg = access.base_reg == 11 ? 10 : 11;
    mov_reg_reg(&code, address_reg, 0);
    add_reg_reg(&code, address_reg, access.base_reg);
    if (access.tpoff != 0) add_imm32(&code, address_reg, static_cast<int32_t>(access.tpoff));
  }

  if (access.address_only) {
    // The resolver result is already the function result in RAX.
  } else if (access.op == Access::MemoryOp::X87Da) {
    const unsigned address_reg = 11;
    mov_reg_reg(&code, address_reg, 0);
    x87_da_memory(&code, access.op_reg, address_reg);
  } else if (access.load) {
    const unsigned address_reg = access.reg == 11 ? 10 : 11;
    mov_reg_reg(&code, address_reg, 0);
    if (access.op == Access::MemoryOp::And) {
      and_reg_memory(&code, access.reg, address_reg, access.wide);
    } else if (access.op == Access::MemoryOp::Add) {
      add_reg_memory(&code, access.reg, address_reg, access.wide);
    } else {
      // The direct form only uses a 32- or 64-bit destination.  Its original
      // REX.W bit is preserved by the synthesized instruction.
      mov_reg_memory(&code, access.reg, address_reg, access.wide);
    }
  } else {
    const unsigned address_reg = access.reg == 11 ? 10 : 11;
    mov_reg_reg(&code, address_reg, 0);
    mov_memory_reg(&code, address_reg, store_value_reg, access.wide);
  }

  if (access.op == Access::MemoryOp::And || access.op == Access::MemoryOp::Add) {
    // pushfq at the start protects the guest flags while the resolver runs.
    // Replace that saved word with the flags produced by AND before the
    // ordinary register/stack cleanup restores it.
    const unsigned flags_reg = access.reg == 10 ? 11 : 10;
    emit(&code, 0x9c);  // pushfq
    pop_reg(&code, flags_reg);
    const int32_t flags_offset = static_cast<int32_t>(
        8 * (saved_count + (align_stack ? 1 : 0)));
    mov_stack_disp_reg(&code, flags_reg, flags_offset);
  }

  if (align_stack) {
    emit(&code, 0x48); emit(&code, 0x83); emit(&code, 0xc4); emit(&code, 8);
  }
  if (access.base_relative) {
    if ((access.load || access.address_only) && access.reg == access.base_reg) {
      emit(&code, 0x48); emit(&code, 0x8d); emit(&code, 0x64); emit(&code, 0x24); emit(&code, 8);
    } else {
      pop_reg(&code, access.base_reg);
    }
  }
  for (size_t i = sizeof(kSavedRegs) / sizeof(kSavedRegs[0]); i-- > 0;) {
    const unsigned reg = kSavedRegs[i];
    if ((access.load || access.address_only) && reg == access.reg) continue;
    pop_reg(&code, reg);
  }
  emit(&code, 0x9d);  // popfq
  for (size_t i = 0; i < relocated_size; ++i) emit(&code, relocated[i]);
  const unsigned return_reg = (access.load || access.address_only) && access.reg == 11 ? 10 : 11;
  mov_imm64(&code, return_reg, return_address);
  push_reg(&code, return_reg);
  emit(&code, 0xc3);  // ret
  return code;
}

bool patch_site(Byte* site, const Access& access, size_t module_id) {
  const size_t page_size = 4096;
  const uintptr_t site_page = reinterpret_cast<uintptr_t>(site) & ~(page_size - 1);
  size_t patch_length = access.length;
  while (patch_length < 5) {
    const size_t next_length = instruction_length(site + patch_length);
    if (next_length == 0) {
      fprintf(stderr, "TLS-rewrite: cannot extend patch at %p after %zu bytes\n",
              site, patch_length);
      fprintf(stderr, "TLS-rewrite: next bytes %02x %02x %02x %02x %02x %02x %02x %02x\n",
              site[patch_length], site[patch_length + 1], site[patch_length + 2],
              site[patch_length + 3], site[patch_length + 4], site[patch_length + 5],
              site[patch_length + 6], site[patch_length + 7]);
      return false;
    }
    patch_length += next_length;
  }
  const uintptr_t return_address = reinterpret_cast<uintptr_t>(site) + patch_length;
  std::vector<Byte> code = make_stub(return_address, module_id, access,
                                     site + access.length, patch_length - access.length);
  Byte* stub = nullptr;
  bool absolute_jump = false;
  bool reused_page = false;
  for (StubPage& page : g_stub_pages) {
    const int64_t page_delta = reinterpret_cast<uintptr_t>(page.base) -
                               (reinterpret_cast<uintptr_t>(site) + 5);
    if (page_delta >= INT32_MIN && page_delta <= INT32_MAX &&
        page.used + code.size() <= page_size) {
      stub = page.base + page.used;
      page.used += (code.size() + 15) & ~static_cast<size_t>(15);
      reused_page = true;
      break;
    }
  }
  // A five-byte near jump keeps the original instruction footprint intact.
  // Windows does not guarantee that an unconstrained allocation is within
  // 2GB of an ELF image, so probe allocation-granularity-aligned hints around
  // the patch site before giving up.
  if (stub == nullptr) for (uintptr_t distance = 0; distance <= 0x7fff0000ULL && stub == nullptr;
       distance += 0x1000000ULL) {
    const uintptr_t hints[] = {site_page + distance, site_page >= distance
        ? site_page - distance : 0};
    for (uintptr_t hint_value : hints) {
      if (hint_value == 0) continue;
      stub = static_cast<Byte*>(VirtualAlloc(reinterpret_cast<void*>(hint_value), page_size,
                                              MEM_RESERVE | MEM_COMMIT,
                                              PAGE_EXECUTE_READWRITE));
      if (stub != nullptr) break;
    }
  }
  if (stub == nullptr) {
    // If the ELF image has no free address within the rel32 range, use an
    // absolute 14-byte jump. This is less compact but keeps real Android
    // libraries loadable on Windows where the PE address layout is unrelated
    // to the ELF image address.
    while (patch_length < 14) {
      const size_t next_length = instruction_length(site + patch_length);
      if (next_length == 0) {
        fprintf(stderr, "TLS-rewrite: cannot extend absolute patch at %p after %zu bytes\n",
                site, patch_length);
        fprintf(stderr, "TLS-rewrite: next bytes %02x %02x %02x %02x %02x %02x %02x %02x\n",
                site[patch_length], site[patch_length + 1], site[patch_length + 2],
                site[patch_length + 3], site[patch_length + 4], site[patch_length + 5],
                site[patch_length + 6], site[patch_length + 7]);
        return false;
      }
      patch_length += next_length;
    }
    const uintptr_t absolute_return = reinterpret_cast<uintptr_t>(site) + patch_length;
    code = make_stub(absolute_return, module_id, access,
                     site + access.length, patch_length - access.length);
    stub = static_cast<Byte*>(VirtualAlloc(nullptr, page_size,
                                            MEM_RESERVE | MEM_COMMIT,
                                            PAGE_EXECUTE_READWRITE));
    absolute_jump = stub != nullptr;
  }
  if (stub == nullptr) {
    fprintf(stderr, "TLS-rewrite: no executable stub page for %p\n", site);
    return false;
  }
  if (code.size() > page_size) {
    fprintf(stderr, "TLS-rewrite: stub too large (%zu) for %p\n", code.size(), site);
    return false;
  }
  // Only register a brand-new VirtualAlloc'd page. On reuse the matching page's
  // `used` bump above already reserved this stub's space; pushing another entry
  // (the old `page.base == stub` test was always true for a reused stub, whose
  // address is base+used, never base) created overlapping entries that later
  // handed out addresses on top of existing stubs, corrupting them.
  if (!reused_page) {
    g_stub_pages.push_back({stub, (code.size() + 15) & ~static_cast<size_t>(15)});
    if (std::getenv("ADAM_CTOR_DEBUG"))
      fprintf(stderr, "[stub] new stub page base=%p size=0x1000 (patch site %p, module %zu)\n",
              static_cast<void*>(stub), static_cast<void*>(site), module_id);
  }
  const int64_t delta = reinterpret_cast<uintptr_t>(stub) -
                        (reinterpret_cast<uintptr_t>(site) + 5);
  if ((!absolute_jump && (delta < INT32_MIN || delta > INT32_MAX)) ||
      code.size() > page_size) {
    fprintf(stderr, "TLS-rewrite: invalid stub placement for %p (absolute=%d delta=%lld)\n",
            site, absolute_jump ? 1 : 0, static_cast<long long>(delta));
    return false;
  }
  std::memcpy(stub, code.data(), code.size());
  DWORD old_protection = 0;
  if (!VirtualProtect(site, patch_length, PAGE_EXECUTE_READWRITE, &old_protection)) {
    fprintf(stderr, "TLS-rewrite: VirtualProtect failed for %p (%lu)\n",
            site, static_cast<unsigned long>(GetLastError()));
    return false;
  }
  if (absolute_jump) {
    site[0] = 0x49; site[1] = 0xbb;
    const uint64_t target = reinterpret_cast<uint64_t>(stub);
    std::memcpy(site + 2, &target, sizeof(target));
    site[10] = 0x41; site[11] = 0xff; site[12] = 0xe3;
    site[13] = 0x90;
  } else {
    site[0] = 0xe9;
    const int32_t relative = static_cast<int32_t>(delta);
    std::memcpy(site + 1, &relative, sizeof(relative));
  }
  for (size_t i = absolute_jump ? 14 : 5; i < patch_length; ++i) site[i] = 0x90;
  DWORD ignored = 0;
  VirtualProtect(site, patch_length, old_protection, &ignored);
  FlushInstructionCache(GetCurrentProcess(), site, patch_length);
  return true;
}

// Open the ELF file by its Windows path and read the section headers to find
// the individual virtual-address ranges covered by executable sections
// (SHF_EXECINSTR) within the given PT_LOAD segment. Keeping separate ranges is
// important: Android ELFs commonly place string/data sections between code
// sections in the same R+E PT_LOAD, and scanning the min/max span treats those
// data bytes as x86 instructions.
static bool find_exec_ranges(const char* path, const ElfW(Ehdr)* ehdr,
                             ElfW(Addr) seg_vaddr, ElfW(Xword) seg_memsz,
                             std::vector<std::pair<size_t, size_t>>* ranges) {
  if (!path || !path[0]) return false;
  if (ehdr->e_shnum == 0 || ehdr->e_shentsize < sizeof(ElfW(Shdr))) return false;
  HANDLE fh = CreateFileA(path, GENERIC_READ,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (fh == INVALID_HANDLE_VALUE) return false;
  bool ok = false;
  ElfW(Shdr)* shdrs = static_cast<ElfW(Shdr)*>(
      malloc(static_cast<size_t>(ehdr->e_shnum) * sizeof(ElfW(Shdr))));
  if (shdrs) {
    LARGE_INTEGER off{}; off.QuadPart = static_cast<LONGLONG>(ehdr->e_shoff);
    LARGE_INTEGER pos{}; pos.QuadPart = 0;
    DWORD to_read = static_cast<DWORD>(ehdr->e_shnum) * sizeof(ElfW(Shdr));
    DWORD nr = 0;
    if (SetFilePointerEx(fh, off, &pos, FILE_BEGIN) &&
        ReadFile(fh, shdrs, to_read, &nr, NULL) && nr == to_read) {
      for (uint16_t k = 0; k < ehdr->e_shnum; ++k) {
        if ((shdrs[k].sh_flags & SHF_EXECINSTR) == 0) continue;
        if (shdrs[k].sh_addr < seg_vaddr ||
            shdrs[k].sh_addr >= seg_vaddr + seg_memsz) continue;
        const size_t sec_start = static_cast<size_t>(shdrs[k].sh_addr - seg_vaddr);
        const size_t sec_size = static_cast<size_t>(shdrs[k].sh_size);
        const size_t sec_end = sec_start + sec_size;
        if (sec_size != 0 && sec_start < seg_memsz)
          ranges->push_back({sec_start, sec_end > seg_memsz ? seg_memsz : sec_end});
      }
      // The section header table was read in full, so the set of executable
      // sections is now authoritative. A library whose only SHF_EXECINSTR
      // section is empty (e.g. libicudata, which parks a multi-megabyte data
      // blob in an R+E PT_LOAD with a zero-length .text) yields no ranges and
      // must be scanned NOT AT ALL — returning success with an empty range set
      // tells the caller to skip it, rather than falling back to scanning the
      // whole segment and decoding locale data as x86 instructions.
      ok = true;
      if (!ranges->empty()) {
        std::sort(ranges->begin(), ranges->end());
        std::vector<std::pair<size_t, size_t>> merged;
        for (const auto& range : *ranges) {
          if (!merged.empty() && range.first <= merged.back().second) {
            if (range.second > merged.back().second) merged.back().second = range.second;
          } else {
            merged.push_back(range);
          }
        }
        ranges->swap(merged);
      }
    }
    free(shdrs);
  }
  CloseHandle(fh);
  return ok;
}

}  // namespace

bool rewrite_x86_64_guest_tls(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                              ElfW(Addr) load_bias, size_t module_id,
                              const char* realpath) {
  for (size_t i = 0; i < phdr_count; ++i) {
    const ElfW(Phdr)& phdr = phdr_table[i];
    if (phdr.p_type != PT_LOAD || (phdr.p_flags & PF_X) == 0) continue;
    Byte* begin = reinterpret_cast<Byte*>(load_bias + phdr.p_vaddr);
    // Android ELFs pack data sections (.dynsym, .dynstr, .hash, .rela.*) and
    // code (.plt, .text) into the same R+E PT_LOAD, with read-only data
    // (.rodata, .eh_frame) after .text.  Read the section headers from disk
    // to restrict scanning to exactly the executable sections.
    std::vector<std::pair<size_t, size_t>> scan_ranges;
    // True once we have an authoritative view of this segment's code extent
    // (from section headers or the DT_JMPREL fallback). When it stays false we
    // have no information and scan the whole segment; when it is true we trust
    // scan_ranges even if it is empty (a data-only library has no code).
    bool have_code_extent = false;
    if (phdr.p_vaddr == 0 && phdr.p_memsz >= sizeof(ElfW(Ehdr))) {
      const ElfW(Ehdr)* ehdr = reinterpret_cast<const ElfW(Ehdr)*>(begin);
      if (ehdr->e_ident[0] == '\x7f' && ehdr->e_ident[1] == 'E' &&
          ehdr->e_ident[2] == 'L' && ehdr->e_ident[3] == 'F') {
        if (find_exec_ranges(realpath, ehdr, phdr.p_vaddr, phdr.p_memsz,
                            &scan_ranges)) {
          have_code_extent = true;
        } else {
          // Fallback: use DT_JMPREL + DT_PLTRELSZ to skip past data sections.
          size_t start_offset = static_cast<size_t>(ehdr->e_phoff) +
                                static_cast<size_t>(ehdr->e_phnum) * sizeof(ElfW(Phdr));
          start_offset = (start_offset + 0xfffUL) & ~static_cast<size_t>(0xfffUL);
          for (size_t j = 0; j < phdr_count; ++j) {
            if (phdr_table[j].p_type != PT_DYNAMIC) continue;
            const ElfW(Dyn)* dyn = reinterpret_cast<const ElfW(Dyn)*>(
                load_bias + phdr_table[j].p_vaddr);
            ElfW(Addr)  jmprel   = 0;
            ElfW(Xword) pltrelsz = 0;
            for (size_t k = 0; k < 256 && dyn[k].d_tag != DT_NULL; ++k) {
              if (dyn[k].d_tag == DT_JMPREL)   jmprel   = dyn[k].d_un.d_ptr;
              if (dyn[k].d_tag == DT_PLTRELSZ) pltrelsz = dyn[k].d_un.d_val;
            }
            if (jmprel != 0 && pltrelsz != 0) {
              const size_t rela_end = static_cast<size_t>(
                  jmprel + pltrelsz - phdr.p_vaddr);
              if (rela_end > start_offset && rela_end <= phdr.p_memsz)
                start_offset = rela_end;
            }
            break;
          }
          scan_ranges.push_back({start_offset, phdr.p_memsz});
          have_code_extent = true;
        }
      }
    }
    // Only scan the whole segment blind when we never learned its code extent.
    // If we did (section headers or the DT_JMPREL fallback) an empty range set
    // means "no code here" and the segment is skipped.
    if (scan_ranges.empty() && !have_code_extent)
      scan_ranges.push_back({0, phdr.p_memsz});
    // Track whether we are at a known instruction boundary. When
    // instruction_length() returns 0 (unrecognised opcode) we advance by 1
    // byte and lose sync; a 0x64 byte reached that way is a data byte inside
    // a non-code section (e.g. .dynsym) that shares the R+E PT_LOAD segment.
    // Only a 0x64 reached from a known boundary is a genuine FS prefix.
    for (const auto& scan_range : scan_ranges) {
      const size_t start_offset = scan_range.first;
      const size_t end_offset = scan_range.second;
      bool at_known_boundary = true;
      for (size_t offset = start_offset; offset + 8 <= end_offset;) {
      Access access = {};
      if (decode(begin + offset, &access)) {
        // The linear sweep can land inside embedded data (e.g. the ICU locale
        // tables in libicudata) whose bytes happen to form a short fs:-prefixed
        // memory op such as "add eax, fs:[rax]" (64 03 00). A genuine static or
        // initial-exec TLS access always carries a disp32 (>= 8 bytes) or uses
        // the absolute fs:[disp32] SIB form, so a base-relative, zero-displacement
        // op shorter than a 5-byte patch site is never real TLS. If such a site
        // also cannot be grown into a patchable 5 bytes (its trailing bytes are
        // data, not instructions), treat the 0x64 as an opaque data byte and
        // resync, instead of aborting the whole image on an unrewritable site.
        if (access.base_relative && access.tpoff == 0 && access.length < 5) {
          size_t probe = access.length;
          while (probe < 5) {
            const size_t n = instruction_length(begin + offset + probe);
            if (n == 0) break;
            probe += n;
          }
          if (probe < 5) {
            offset++;
            at_known_boundary = false;
            continue;
          }
        }
        // Clang's x86-64 initial-exec lowering used by the Android NDK is
        // commonly: mov GOT(%rip),reg; fs:0; add reg,rax; [load/store].
        // Rewrite the complete sequence so the GOT value is not interpreted
        // relative to the host thread pointer.
        if (access.tpoff == 0 && access.load && offset >= 7 &&
            begin[offset - 7] == 0x48 && begin[offset - 6] == 0x8b &&
            (begin[offset - 5] == 0x0d || begin[offset - 5] == 0x15)) {
          int32_t got_disp = 0;
          std::memcpy(&got_disp, begin + offset - 4, sizeof(got_disp));
          const uintptr_t got_address = reinterpret_cast<uintptr_t>(begin + offset) + got_disp;
          int64_t tpoff = 0;
          std::memcpy(&tpoff, reinterpret_cast<const void*>(got_address), sizeof(tpoff));
          const Byte* tail = begin + offset + access.length;
          const Byte* add = tail;
          if (add[0] == 0x48 && add[1] == 0x01 &&
              (add[2] == 0xc8 || add[2] == 0xd0)) {
            Access rewritten = access;
            rewritten.tpoff = tpoff;
            rewritten.tp_relative = false;
            if (tail[3] == 0x8b && tail[4] == 0x00) {
              rewritten.length += 5;
              rewritten.load = true;
              rewritten.reg = 0;
              rewritten.wide = false;
            } else if (tail[3] == 0x89 && tail[4] == 0x08) {
              rewritten.length += 5;
              rewritten.load = false;
              rewritten.reg = 1;  // ecx, the source in the NDK lowering
              rewritten.wide = false;
            } else if (tail[3] == 0x5d && tail[4] == 0xc3) {
              rewritten.length += 3;
              rewritten.address_only = true;
              rewritten.load = true;
              rewritten.reg = 0;
              rewritten.wide = true;
            } else {
              if (!patch_site(begin + offset, access, module_id)) return false;
              offset += access.length;
              at_known_boundary = true;
              continue;
            }
            if (!patch_site(begin + offset, rewritten, module_id)) return false;
            offset += rewritten.length;
            at_known_boundary = true;
            continue;
          }
        }
        if (!patch_site(begin + offset, access, module_id)) {
          fprintf(stderr, "TLS-rewrite: patch_site FAIL at 0x%zx bytes %02x %02x %02x %02x %02x len=%zu\n",
                  offset, begin[offset], begin[offset+1], begin[offset+2], begin[offset+3], begin[offset+4], access.length);
          return false;
        }
        offset += access.length;
        at_known_boundary = true;
      } else {
        // A segment override on a register-only form is ignored by x86 and
        // is emitted by some Android code generators around ABI shuffles. It
        // is not a TLS access, so skip the complete instruction rather than
        // failing closed on the decorative 0x64 prefix.
        const size_t ignored_length = ignored_fs_prefix_length(begin + offset);
        if (ignored_length != 0) {
          offset += ignored_length;
          at_known_boundary = true;
          continue;
        }
        if (begin[offset] == 0x64) {
          if (!at_known_boundary) {
            // Data byte reached via a 1-byte advance from an unrecognised
            // instruction — not an FS-prefix, skip it.
            offset++;
            continue;
          }
          // A segment prefix is also legal on instructions for which the
          // segment is ignored, and Android binaries contain embedded byte
          // tables in executable sections. Treat an unrecognised prefix as a
          // one-byte opaque instruction and lose boundary synchronisation;
          // this prevents data bytes from being mistaken for TLS accesses.
          // Recognised FS memory forms still go through decode() above and
          // are rewritten, while genuinely unsupported forms fail only if
          // they subsequently decode as a supported TLS access.
          fprintf(stderr, "TLS-rewrite: skipping opaque FS-prefix at 0x%zx bytes %02x %02x %02x %02x %02x\n",
                  offset, begin[offset], begin[offset+1], begin[offset+2], begin[offset+3], begin[offset+4]);
          offset++;
          at_known_boundary = false;
          continue;
        }
        const size_t length = instruction_length(begin + offset);
        if (length == 0) {
          at_known_boundary = false;
          offset++;
        } else {
          const Byte op0 = begin[offset + (((begin[offset] & 0xf0) == 0x40) ? 1 : 0)];
          at_known_boundary = true;
          offset += length;
          // After an unconditional transfer (jmp rel8/rel32, ret) the bytes up
          // to the next instruction are alignment padding (0x00 or 0xcc int3).
          // A linear sweep would otherwise decode 0x00 as "add [mem],reg" and
          // swallow a following fs: access (e.g. "mov rax,fs:[0]"), leaving it
          // unrewritten. Skip the padding so the sweep re-syncs to real code.
          if (op0 == 0xe9 || op0 == 0xeb || op0 == 0xc3 || op0 == 0xc2) {
            while (offset + 8 <= end_offset &&
                   (begin[offset] == 0x00 || begin[offset] == 0xcc))
              offset++;
          }
        }
      }
    }
  }
  }
  return true;
}

#endif
