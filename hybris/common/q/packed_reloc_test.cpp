/*
 * Regression coverage for Android's APS2 packed relocation stream.
 */

#include "linker_reloc_iterators.h"
#include "linker_sleb128.h"
#include "x86_64_relocation.h"

#include <stdint.h>

#include <vector>

#include <gtest/gtest.h>

namespace {

void append_sleb128(std::vector<uint8_t>* encoding, int64_t value) {
  bool more = true;
  while (more) {
    uint8_t byte = static_cast<uint8_t>(value & 0x7f);
    value >>= 7;
    const bool sign_bit_set = (byte & 0x40) != 0;
    more = !((value == 0 && !sign_bit_set) || (value == -1 && sign_bit_set));
    if (more) byte |= 0x80;
    encoding->push_back(byte);
  }
}

uint64_t read_u64(const unsigned char* bytes) {
  uint64_t value = 0;
  for (size_t index = 0; index < sizeof(value); ++index) {
    value |= static_cast<uint64_t>(bytes[index]) << (index * 8);
  }
  return value;
}

}  // namespace

TEST(packed_reloc, aps2_relative_and_symbol_relocation) {
  constexpr uint64_t image_vaddr = 0x400000;
  constexpr uint64_t relative_offset = 0x10;
  constexpr uint64_t symbol_offset = 0x18;
  constexpr int64_t relative_addend = 0x20;
  constexpr uint64_t symbol_value = 0x123456789abcdef0ULL;

  std::vector<uint8_t> encoding = {'A', 'P', 'S', '2'};
  // Two entries, with the first entry starting at the image virtual address
  // plus relative_offset, as it appears in an ELF relocation table.
  append_sleb128(&encoding, 2);
  append_sleb128(&encoding, image_vaddr + relative_offset);
  // One entry: offset delta, info, and addend are all grouped.
  append_sleb128(&encoding, 1);
  append_sleb128(&encoding, RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG |
                              RELOCATION_GROUPED_BY_INFO_FLAG |
                              RELOCATION_GROUPED_BY_ADDEND_FLAG |
                              RELOCATION_GROUP_HAS_ADDEND_FLAG);
  append_sleb128(&encoding, 0);
  append_sleb128(&encoding, ELF64_R_INFO(0, R_X86_64_RELATIVE));
  append_sleb128(&encoding, relative_addend);
  // One entry: offset and addend are deltas, while info is per-entry.
  append_sleb128(&encoding, 1);
  append_sleb128(&encoding, RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG |
                              RELOCATION_GROUP_HAS_ADDEND_FLAG);
  append_sleb128(&encoding, symbol_offset - relative_offset);
  append_sleb128(&encoding, ELF64_R_INFO(1, R_X86_64_GLOB_DAT));
  // Addends in APS2 are delta encoded; return from 0x20 to zero.
  append_sleb128(&encoding, -relative_addend);

  unsigned char image[64] = {};
  q_x86_64_symbol symbol = {};
  symbol.value = symbol_value;

  packed_reloc_iterator<sleb128_decoder> iterator(
      sleb128_decoder(encoding.data() + 4, encoding.size() - 4));

  ASSERT_TRUE(iterator.has_next());
  Elf64_Rela* relative = iterator.next();
  ASSERT_NE(nullptr, relative);
  EXPECT_EQ(image_vaddr + relative_offset, relative->r_offset);
  EXPECT_EQ(ELF64_R_INFO(0, R_X86_64_RELATIVE), relative->r_info);
  EXPECT_EQ(relative_addend, relative->r_addend);
  q_x86_64_relocation relative_reloc = {
      R_X86_64_RELATIVE, relative->r_offset, relative->r_addend};
  EXPECT_EQ(Q_RELOC_OK, q_x86_64_apply_relocation(
                            image, sizeof(image), image_vaddr,
                            &relative_reloc, nullptr));
  EXPECT_EQ(static_cast<uint64_t>(reinterpret_cast<uintptr_t>(image)) -
                image_vaddr + relative_addend,
            read_u64(image + relative_offset));

  ASSERT_TRUE(iterator.has_next());
  Elf64_Rela* symbol_reloc = iterator.next();
  ASSERT_NE(nullptr, symbol_reloc);
  EXPECT_EQ(image_vaddr + symbol_offset, symbol_reloc->r_offset);
  EXPECT_EQ(ELF64_R_INFO(1, R_X86_64_GLOB_DAT), symbol_reloc->r_info);
  EXPECT_EQ(0, symbol_reloc->r_addend);
  q_x86_64_relocation symbol_relocation = {
      R_X86_64_GLOB_DAT, symbol_reloc->r_offset, symbol_reloc->r_addend};
  EXPECT_EQ(Q_RELOC_OK, q_x86_64_apply_relocation(
                            image, sizeof(image), image_vaddr,
                            &symbol_relocation, &symbol));
  EXPECT_EQ(symbol_value, read_u64(image + symbol_offset));
  EXPECT_FALSE(iterator.has_next());
  EXPECT_TRUE(iterator.valid());
}

namespace {

void expect_invalid_aps2(const std::vector<uint8_t>& encoding) {
  ASSERT_GE(encoding.size(), 4U);
  packed_reloc_iterator<sleb128_decoder> iterator(
      sleb128_decoder(encoding.data() + 4, encoding.size() - 4));
  while (iterator.has_next()) {
    EXPECT_EQ(nullptr, iterator.next());
  }
  EXPECT_FALSE(iterator.valid());
  EXPECT_FALSE(iterator.has_next());
  EXPECT_EQ(nullptr, iterator.next());
}

}  // namespace

TEST(packed_reloc, malformed_streams_are_rejected) {
  expect_invalid_aps2({'A', 'P', 'S', '2'});

  std::vector<uint8_t> count_only = {'A', 'P', 'S', '2'};
  append_sleb128(&count_only, 1);
  expect_invalid_aps2(count_only);

  std::vector<uint8_t> zero_group = {'A', 'P', 'S', '2'};
  append_sleb128(&zero_group, 1);
  append_sleb128(&zero_group, 0);
  append_sleb128(&zero_group, 0);
  append_sleb128(&zero_group, 0);
  expect_invalid_aps2(zero_group);

  std::vector<uint8_t> oversized_group = {'A', 'P', 'S', '2'};
  append_sleb128(&oversized_group, 1);
  append_sleb128(&oversized_group, 0);
  append_sleb128(&oversized_group, 2);
  append_sleb128(&oversized_group, RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG |
                                      RELOCATION_GROUPED_BY_INFO_FLAG);
  append_sleb128(&oversized_group, 0);
  append_sleb128(&oversized_group, 0);
  expect_invalid_aps2(oversized_group);

  std::vector<uint8_t> unknown_flags = {'A', 'P', 'S', '2'};
  append_sleb128(&unknown_flags, 1);
  append_sleb128(&unknown_flags, 0);
  append_sleb128(&unknown_flags, 1);
  append_sleb128(&unknown_flags, 0x10);
  expect_invalid_aps2(unknown_flags);
}
