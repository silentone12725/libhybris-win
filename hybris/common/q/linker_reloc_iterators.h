/*
 * Copyright (C) 2015 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma once

#include "linker.h"

#include <string.h>

const size_t RELOCATION_GROUPED_BY_INFO_FLAG = 1;
const size_t RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG = 2;
const size_t RELOCATION_GROUPED_BY_ADDEND_FLAG = 4;
const size_t RELOCATION_GROUP_HAS_ADDEND_FLAG = 8;

class plain_reloc_iterator {
#if defined(USE_RELA)
  typedef ElfW(Rela) rel_t;
#else
  typedef ElfW(Rel) rel_t;
#endif
 public:
  plain_reloc_iterator(rel_t* rel_array, size_t count)
      : begin_(rel_array), end_(begin_ + count), current_(begin_) {}

  bool has_next() {
    return current_ < end_;
  }

  bool valid() const { return true; }

  rel_t* next() {
    return current_++;
  }
 private:
  rel_t* const begin_;
  rel_t* const end_;
  rel_t* current_;

  DISALLOW_COPY_AND_ASSIGN(plain_reloc_iterator);
};

template <typename decoder_t>
class packed_reloc_iterator {
#if defined(USE_RELA)
  typedef ElfW(Rela) rel_t;
#else
  typedef ElfW(Rel) rel_t;
#endif
 public:
  explicit packed_reloc_iterator(decoder_t&& decoder)
      : decoder_(decoder), relocation_count_(0), group_size_(0), group_flags_(0),
        group_r_offset_delta_(0), relocation_index_(0), relocation_group_index_(0),
        valid_(true) {
    // initialize fields
    memset(&reloc_, 0, sizeof(reloc_));
    if (!decoder_.pop_front(&relocation_count_) ||
        !decoder_.pop_front(&reloc_.r_offset)) {
      valid_ = false;
    }
  }

  bool has_next() const {
    return valid_ && relocation_index_ < relocation_count_;
  }

  bool valid() const { return valid_; }

  rel_t* next() {
    if (!valid_) return nullptr;
    if (relocation_group_index_ == group_size_) {
      if (!read_group_fields()) {
        return nullptr;
      }
    }

    size_t value = 0;
    if (is_relocation_grouped_by_offset_delta()) {
      reloc_.r_offset += group_r_offset_delta_;
    } else if (!decoder_.pop_front(&value)) {
      valid_ = false;
      return nullptr;
    } else {
      reloc_.r_offset += value;
    }

    if (!is_relocation_grouped_by_info()) {
      if (!decoder_.pop_front(&value)) {
        valid_ = false;
        return nullptr;
      }
      reloc_.r_info = value;
    }

#if defined(USE_RELA)
    if (is_relocation_group_has_addend() &&
        !is_relocation_grouped_by_addend()) {
      if (!decoder_.pop_front(&value)) {
        valid_ = false;
        return nullptr;
      }
      reloc_.r_addend += value;
    }
#endif

    relocation_index_++;
    relocation_group_index_++;

    return &reloc_;
  }
 private:
  bool read_group_fields() {
    size_t value = 0;
    if (!decoder_.pop_front(&group_size_) || !decoder_.pop_front(&group_flags_)) {
      valid_ = false;
      return false;
    }
    if (group_size_ == 0 || group_size_ > relocation_count_ - relocation_index_ ||
        (group_flags_ & ~(RELOCATION_GROUPED_BY_INFO_FLAG |
                          RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG |
                          RELOCATION_GROUPED_BY_ADDEND_FLAG |
                          RELOCATION_GROUP_HAS_ADDEND_FLAG)) != 0) {
      valid_ = false;
      return false;
    }

    if (is_relocation_grouped_by_offset_delta()) {
      if (!decoder_.pop_front(&group_r_offset_delta_)) {
        valid_ = false;
        return false;
      }
    }

    if (is_relocation_grouped_by_info()) {
      if (!decoder_.pop_front(&reloc_.r_info)) {
        valid_ = false;
        return false;
      }
    }

    if (is_relocation_group_has_addend() &&
        is_relocation_grouped_by_addend()) {
#if !defined(USE_RELA)
      // This platform does not support rela, and yet we have it encoded in android_rel section.
      DL_ERR("unexpected r_addend in android.rel section");
      valid_ = false;
      return false;
#else
      if (!decoder_.pop_front(&value)) {
        valid_ = false;
        return false;
      }
      reloc_.r_addend += value;
    } else if (!is_relocation_group_has_addend()) {
      reloc_.r_addend = 0;
#endif
    }

    relocation_group_index_ = 0;
    return true;
  }

  bool is_relocation_grouped_by_info() {
    return (group_flags_ & RELOCATION_GROUPED_BY_INFO_FLAG) != 0;
  }

  bool is_relocation_grouped_by_offset_delta() {
    return (group_flags_ & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG) != 0;
  }

  bool is_relocation_grouped_by_addend() {
    return (group_flags_ & RELOCATION_GROUPED_BY_ADDEND_FLAG) != 0;
  }

  bool is_relocation_group_has_addend() {
    return (group_flags_ & RELOCATION_GROUP_HAS_ADDEND_FLAG) != 0;
  }

  decoder_t decoder_;
  size_t relocation_count_;
  size_t group_size_;
  size_t group_flags_;
  size_t group_r_offset_delta_;
  size_t relocation_index_;
  size_t relocation_group_index_;
  rel_t reloc_;
  bool valid_;
};
