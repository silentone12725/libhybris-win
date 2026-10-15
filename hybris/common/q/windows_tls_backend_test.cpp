/*
 * Copyright (C) 2026 The libhybris developers
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "windows_tls_backend.h"

#include <assert.h>
#include <stdint.h>

#include <atomic>
#include <thread>

namespace {

std::atomic<int> old_destructor_calls(0);
std::atomic<int> new_destructor_calls(0);
std::atomic<int> thread_destructor_calls(0);

void old_destructor(void* block, size_t size) {
  assert(block != nullptr);
  assert(size == 16);
  old_destructor_calls.fetch_add(1, std::memory_order_relaxed);
}

void new_destructor(void* block, size_t size) {
  assert(block != nullptr);
  assert(size == 16);
  new_destructor_calls.fetch_add(1, std::memory_order_relaxed);
}

void thread_destructor(void* block, size_t size) {
  assert(block != nullptr);
  assert(size == 8);
  thread_destructor_calls.fetch_add(1, std::memory_order_relaxed);
}

}  // namespace

int main() {
  q_tls::TlsBackend* backend = q_tls::backend_create();
  assert(backend != nullptr);

  const unsigned char old_init[] = {0x11, 0x22, 0x33, 0x44};
  const q_tls::TlsModule old_module = {1, old_init, sizeof(old_init), 16, 32, old_destructor};
  assert(q_tls::backend_register_module(backend, old_module));

  const q_tls::TlsModule invalid_alignment = {99, nullptr, 0, 8, 3, nullptr};
  assert(!q_tls::backend_register_module(backend, invalid_alignment));

  q_tls::TlsContext* context = q_tls::context_create(backend);
  assert(context != nullptr);
  void** slots = q_tls::context_slots(context);
  assert(slots != nullptr);
  for (size_t i = 0; i < 16; ++i) assert(slots[i] == nullptr);
  assert(q_tls::context_attach(backend, context));
  assert(q_tls::context_current(backend) == context);
  assert(q_tls::context_current_or_create(backend) == context);

  const q_tls::TlsIndex base_index = {1, 0};
  unsigned char* base = static_cast<unsigned char*>(q_tls::get_addr(backend, base_index));
  assert(base != nullptr);
  assert(reinterpret_cast<uintptr_t>(base) % 32 == 0);
  assert(base[0] == 0x11 && base[1] == 0x22 && base[2] == 0x33 && base[3] == 0x44);
  for (size_t i = 4; i < 16; ++i) assert(base[i] == 0);
  assert(q_tls::get_addr(backend, q_tls::TlsIndex{1, 16}) == nullptr);
  assert(q_tls::get_addr(backend, q_tls::TlsIndex{1, 4}) == base + 4);

  std::thread isolated_thread([&] {
    q_tls::TlsContext* thread_context = q_tls::context_current_or_create(backend);
    assert(thread_context != nullptr);
    unsigned char* thread_base = static_cast<unsigned char*>(q_tls::get_addr(backend, base_index));
    assert(thread_base != nullptr);
    assert(thread_base != base);
    assert(thread_base[0] == 0x11);
    thread_base[0] = 0xee;
  });
  isolated_thread.join();
  assert(base[0] == 0x11);
  assert(old_destructor_calls.load(std::memory_order_relaxed) == 1);

  assert(!q_tls::backend_destroy(backend));
  assert(q_tls::backend_unregister_module(backend, 1));
  assert(q_tls::get_addr(backend, base_index) == nullptr);

  const unsigned char new_init[] = {0xa1, 0xb2};
  const q_tls::TlsModule new_module = {1, new_init, sizeof(new_init), 16, 32, new_destructor};
  assert(q_tls::backend_register_module(backend, new_module));
  unsigned char* replacement =
      static_cast<unsigned char*>(q_tls::get_addr(backend, base_index));
  assert(replacement != nullptr);
  assert(replacement[0] == 0xa1 && replacement[1] == 0xb2);
  for (size_t i = 2; i < 16; ++i) assert(replacement[i] == 0);
  assert(old_destructor_calls.load(std::memory_order_relaxed) == 2);

  assert(q_tls::context_detach(backend));
  assert(q_tls::context_current(backend) == nullptr);
  assert(new_destructor_calls.load(std::memory_order_relaxed) == 1);
  assert(q_tls::context_destroy(context));
  assert(new_destructor_calls.load(std::memory_order_relaxed) == 1);
  assert(q_tls::backend_unregister_module(backend, 1));

  const q_tls::TlsModule thread_module = {2, nullptr, 0, 8, 64, thread_destructor};
  assert(q_tls::backend_register_module(backend, thread_module));
  std::thread cleanup_thread([&] {
    assert(q_tls::context_current_or_create(backend) != nullptr);
    assert(q_tls::get_addr(backend, q_tls::TlsIndex{2, 0}) != nullptr);
  });
  cleanup_thread.join();
  assert(thread_destructor_calls.load(std::memory_order_relaxed) == 1);
  assert(q_tls::backend_unregister_module(backend, 2));

  assert(q_tls::backend_destroy(backend));
  return 0;
}
