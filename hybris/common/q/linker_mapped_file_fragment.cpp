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

#include "linker_mapped_file_fragment.h"
#if defined(_WIN32)
#include "hybris_compat.h"
#include <stdint.h>
#include <stdlib.h>
#else
#include "linker_debug.h"
#include "linker_utils.h"

#include <inttypes.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

MappedFileFragment::MappedFileFragment() : map_start_(nullptr), map_size_(0),
                                           data_(nullptr), size_ (0)
{ }

MappedFileFragment::~MappedFileFragment() {
  if (map_start_ != nullptr) {
#if defined(_WIN32)
    free(map_start_);
#else
    munmap(map_start_, map_size_);
#endif
  }
}

bool MappedFileFragment::Map(mapped_file_handle_t file, mapped_file_offset_t base_offset,
                             size_t elf_offset, size_t size) {
#if defined(_WIN32)
  if (file == nullptr || base_offset < 0 || size == 0) {
    return false;
  }

  uint64_t offset = static_cast<uint64_t>(base_offset);
  if (static_cast<uint64_t>(elf_offset) > UINT64_MAX - offset) {
    return false;
  }
  offset += static_cast<uint64_t>(elf_offset);

  const uint64_t page_min = offset & ~static_cast<uint64_t>(PAGE_SIZE - 1);
  const uint64_t page_offset = offset - page_min;
  if (static_cast<uint64_t>(size) > UINT64_MAX - offset) {
    return false;
  }
  uint64_t end_offset = offset + static_cast<uint64_t>(size);
  if (page_offset > UINT64_MAX - end_offset) {
    return false;
  }
  end_offset += page_offset;

  const uint64_t map_size64 = end_offset - page_min;
  if (map_size64 == 0 || map_size64 > static_cast<uint64_t>(SIZE_MAX) ||
      map_size64 > UINT32_MAX) {
    return false;
  }

  const size_t map_size = static_cast<size_t>(map_size64);
  uint8_t* map_start = static_cast<uint8_t*>(calloc(1, map_size));
  if (map_start == nullptr || page_min >= file->size) {
    free(map_start);
    return false;
  }
  const uint64_t available = file->size - page_min;
  const size_t read_size = available < map_size64 ? static_cast<size_t>(available) : map_size;
  if (!win_elf_file_read_at(file, map_start, read_size, page_min)) {
    free(map_start);
    return false;
  }

  map_start_ = map_start;
  map_size_ = map_size;
  data_ = map_start + static_cast<size_t>(page_offset);
  size_ = size;
  return true;
#else
  off64_t offset;
  CHECK(safe_add(&offset, base_offset, elf_offset));

  off64_t page_min = page_start(offset);
  off64_t end_offset;

  CHECK(safe_add(&end_offset, offset, size));
  CHECK(safe_add(&end_offset, end_offset, page_offset(offset)));

  size_t map_size = static_cast<size_t>(end_offset - page_min);
  CHECK(map_size >= size);

  uint8_t* map_start = static_cast<uint8_t*>(
                          mmap64(nullptr, map_size, PROT_READ, MAP_PRIVATE, file, page_min));

  if (map_start == MAP_FAILED) {
    return false;
  }

  map_start_ = map_start;
  map_size_ = map_size;

  data_ = map_start + page_offset(offset);
  size_ = size;

  return true;
#endif
}
