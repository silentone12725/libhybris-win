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

#include <stdint.h>

#include <async_safe/log.h>

#include "linker_debug.h"

// Helper classes for decoding LEB128, used in packed relocation data.
// http://en.wikipedia.org/wiki/LEB128

class sleb128_decoder {
 public:
  sleb128_decoder(const uint8_t* buffer, size_t count)
      : current_(buffer), end_(buffer + count), failed_(false) { }

  bool pop_front(size_t* value_out) {
    if (value_out == nullptr || failed_) return false;
    size_t value = 0;
    static const size_t size = CHAR_BIT * sizeof(value);

    size_t shift = 0;
    uint8_t byte;

    do {
      if (current_ >= end_) {
        failed_ = true;
        return false;
      }
      byte = *current_++;
      const size_t payload = byte & 127;
      if (shift >= size ||
          (shift == size - 1 && payload != 0 && payload != 1 && payload != 127)) {
        failed_ = true;
        return false;
      }
      value |= (payload << shift);
      shift += 7;
    } while (byte & 128);

    if (shift < size && (byte & 64)) {
      value |= -(static_cast<size_t>(1) << shift);
    }

    *value_out = value;
    return true;
  }

  bool failed() const { return failed_; }

 private:
  const uint8_t* current_;
  const uint8_t* const end_;
  bool failed_;
};
