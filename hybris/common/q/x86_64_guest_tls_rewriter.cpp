/* SPDX-License-Identifier: BSD-3-Clause */
#include "x86_64_guest_tls_rewriter.h"

#if defined(_WIN32) && defined(__x86_64__)

#include <windows.h>

#include <cstdint>
#include <cstring>
#include <vector>

#include "linker_globals.h"
#include "linker_tls.h"

namespace {

using Byte = unsigned char;

struct Access {
  size_t length;
  unsigned reg;
  unsigned base_reg;
  bool load;
  bool wide;
  bool address_only;
  bool base_relative;
  bool tp_relative;
  int64_t tpoff;
};

static bool decode(const Byte* p, Access* out) {
  size_t i = 0;
  if (p[i++] != 0x64) return false;
  Byte rex = 0;
  if ((p[i] & 0xf0) == 0x40) rex = p[i++];
  const Byte opcode = p[i++];
  if (opcode != 0x8b && opcode != 0x89) return false;
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
  out->load = opcode == 0x8b;
  out->wide = (rex & 8) != 0;
  out->address_only = false;
  out->base_relative = !absolute;
  out->tp_relative = absolute;
  out->tpoff = displacement;
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
  while (p[i] == 0x66 || p[i] == 0x67 || p[i] == 0xf2 || p[i] == 0xf3) ++i;
  if ((p[i] & 0xf0) == 0x40) ++i;
  const Byte opcode = p[i++];
  if (opcode == 0x0f) {
    const Byte extended = p[i++];
    if (extended >= 0x80 && extended <= 0x8f) return i + 4;
    if (extended >= 0x90 && extended <= 0x9f) return i + 1;
    return 0;
  }
  bool has_modrm = false;
  size_t immediate = 0;
  switch (opcode) {
    case 0x01: case 0x03: case 0x09: case 0x0b: case 0x21: case 0x23:
    case 0x29: case 0x2b: case 0x31: case 0x33: case 0x39: case 0x3b:
    case 0x8b: case 0x89: case 0x8d: case 0x85: case 0xff:
      has_modrm = true;
      break;
    case 0x81: case 0xc7:
      has_modrm = true;
      immediate = 4;
      break;
    case 0xa9:
      return i + 4;
    case 0x83: case 0xc1:
      has_modrm = true;
      immediate = 1;
      break;
    case 0x90: case 0xc3: case 0xcc: case 0x5d:
      return i;
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
    if ((access.load || access.address_only) && reg == access.reg &&
        (!access.base_relative || reg != access.base_reg)) continue;
    push_reg(&code, reg);
  }
  if (access.base_relative) push_reg(&code, access.base_reg);
  const size_t saved_count = sizeof(kSavedRegs) / sizeof(kSavedRegs[0]) -
      ((access.load || access.address_only) &&
       (!access.base_relative || access.reg != access.base_reg) ? 1 : 0) +
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
  if (!access.load && !access.address_only) {
    // r12/r13 are callee-saved in the SysV guest ABI, so they survive the
    // resolver call while the original source register may be call-clobbered.
    mov_reg_reg(&code, store_value_reg, access.reg);
  }
  mov_imm64(&code, 11, resolver);
  emit(&code, 0x41); emit(&code, 0xff); emit(&code, 0xd3);  // call r11

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
  } else if (access.load) {
    const unsigned address_reg = access.reg == 11 ? 10 : 11;
    mov_reg_reg(&code, address_reg, 0);
    // The direct form only uses a 32- or 64-bit destination.  Its original
    // REX.W bit is preserved by the synthesized instruction.
    mov_reg_memory(&code, access.reg, address_reg, access.wide);
  } else {
    const unsigned address_reg = access.reg == 11 ? 10 : 11;
    mov_reg_reg(&code, address_reg, 0);
    mov_memory_reg(&code, address_reg, store_value_reg, access.wide);
  }

  if (align_stack) {
    emit(&code, 0x48); emit(&code, 0x83); emit(&code, 0xc4); emit(&code, 8);
  }
  for (size_t i = sizeof(kSavedRegs) / sizeof(kSavedRegs[0]); i-- > 0;) {
    const unsigned reg = kSavedRegs[i];
    if ((access.load || access.address_only) && reg == access.reg &&
        (!access.base_relative || reg != access.base_reg)) continue;
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
    if (next_length == 0) return false;
    patch_length += next_length;
  }
  const uintptr_t return_address = reinterpret_cast<uintptr_t>(site) + patch_length;
  std::vector<Byte> code = make_stub(return_address, module_id, access,
                                      site + access.length, patch_length - access.length);
  Byte* stub = nullptr;
  for (StubPage& page : g_stub_pages) {
    const int64_t page_delta = reinterpret_cast<uintptr_t>(page.base) -
                               (reinterpret_cast<uintptr_t>(site) + 5);
    if (page_delta >= INT32_MIN && page_delta <= INT32_MAX &&
        page.used + code.size() <= page_size) {
      stub = page.base + page.used;
      page.used += (code.size() + 15) & ~static_cast<size_t>(15);
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
  if (stub == nullptr) return false;
  if (code.size() > page_size) return false;
  bool is_new_page = true;
  for (const StubPage& page : g_stub_pages) if (page.base == stub) is_new_page = false;
  if (is_new_page) {
    g_stub_pages.push_back({stub, (code.size() + 15) & ~static_cast<size_t>(15)});
  }
  const int64_t delta = reinterpret_cast<uintptr_t>(stub) -
                        (reinterpret_cast<uintptr_t>(site) + 5);
  if (delta < INT32_MIN || delta > INT32_MAX || code.size() > page_size) return false;
  std::memcpy(stub, code.data(), code.size());
  DWORD old_protection = 0;
  if (!VirtualProtect(site, patch_length, PAGE_EXECUTE_READWRITE, &old_protection)) return false;
  site[0] = 0xe9;
  const int32_t relative = static_cast<int32_t>(delta);
  std::memcpy(site + 1, &relative, sizeof(relative));
  for (size_t i = 5; i < patch_length; ++i) site[i] = 0x90;
  DWORD ignored = 0;
  VirtualProtect(site, patch_length, old_protection, &ignored);
  FlushInstructionCache(GetCurrentProcess(), site, patch_length);
  return true;
}

}  // namespace

bool rewrite_x86_64_guest_tls(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                              ElfW(Addr) load_bias, size_t module_id) {
  for (size_t i = 0; i < phdr_count; ++i) {
    const ElfW(Phdr)& phdr = phdr_table[i];
    if (phdr.p_type != PT_LOAD || (phdr.p_flags & PF_X) == 0) continue;
    Byte* begin = reinterpret_cast<Byte*>(load_bias + phdr.p_vaddr);
    for (size_t offset = 0; offset + 8 <= phdr.p_memsz;) {
      Access access = {};
      if (decode(begin + offset, &access)) {
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
              continue;
            }
            if (!patch_site(begin + offset, rewritten, module_id)) return false;
            offset += rewritten.length;
            continue;
          }
        }
        if (!patch_site(begin + offset, access, module_id)) return false;
        offset += access.length;
      } else {
        ++offset;
      }
    }
  }
  return true;
}

#endif
