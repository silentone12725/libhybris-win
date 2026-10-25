/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "linker_tls.h"

#include <vector>

#if defined(_WIN32)
#include <mutex>
#include "windows_tls_backend.h"
#endif

#include <android/versioning.h>
#include "async_safe/CHECK.h"
#include "private/ScopedRWLock.h"
#include "private/ScopedSignalBlocker.h"
#include "private/bionic_defs.h"
#include "private/bionic_elf_tls.h"
#include "private/bionic_globals.h"
#include "private/linker_native_bridge.h"
#include "linker_main.h"
#include "linker_soinfo.h"
#include <stdint.h>

__LIBC_HIDDEN__ _Atomic(size_t) __libc_tls_generation_copy = {SIZE_MAX};

static bool g_static_tls_finished;
static std::vector<TlsModule> g_tls_modules;

#if defined(_WIN32)
static q_tls::TlsBackend* g_windows_tls_backend;
static std::once_flag g_windows_tls_backend_once;

static q_tls::TlsBackend* get_windows_tls_backend() {
  std::call_once(g_windows_tls_backend_once, [] {
    g_windows_tls_backend = q_tls::backend_create();
  });
  return g_windows_tls_backend;
}
#endif

static size_t get_unused_module_index() {
  for (size_t i = 0; i < g_tls_modules.size(); ++i) {
    if (g_tls_modules[i].soinfo_ptr == nullptr) {
      return i;
    }
  }
  g_tls_modules.push_back({});
  __libc_shared_globals()->tls_modules.module_count = g_tls_modules.size();
  __libc_shared_globals()->tls_modules.module_table = g_tls_modules.data();
  return g_tls_modules.size() - 1;
}

static void register_tls_module(soinfo* si, size_t static_offset) {
  TlsModules& libc_modules = __libc_shared_globals()->tls_modules;

  // The global TLS module table points at the std::vector of modules declared
  // in this file, so acquire a write lock before modifying the std::vector.
  ScopedSignalBlocker ssb;
  ScopedWriteLock locker(&libc_modules.rwlock);

  size_t module_idx = get_unused_module_index();

  soinfo_tls* si_tls = si->get_tls();
  si_tls->module_id = __tls_module_idx_to_id(module_idx);

  const size_t new_generation = ++libc_modules.generation;
  __libc_tls_generation_copy = new_generation;
  if (libc_modules.generation_libc_so != nullptr) {
    *libc_modules.generation_libc_so = new_generation;
  }

  g_tls_modules[module_idx].segment = si_tls->segment;
  g_tls_modules[module_idx].static_offset = static_offset;
  g_tls_modules[module_idx].first_generation = new_generation;
  g_tls_modules[module_idx].soinfo_ptr = si;

#if defined(_WIN32)
  const TlsModule& segment = g_tls_modules[module_idx];
  q_tls::TlsModule windows_module = {
      si_tls->module_id,
      segment.static_offset,
      segment.segment.init_ptr,
      segment.segment.init_size,
      segment.segment.size,
      segment.segment.alignment,
      nullptr};
  q_tls::TlsBackend* backend = get_windows_tls_backend();
  CHECK(backend != nullptr);
  CHECK(q_tls::backend_set_static_layout(backend,
                                        __libc_shared_globals()->static_tls_layout.size(),
                                        __libc_shared_globals()->static_tls_layout.offset_thread_pointer()));
  CHECK(q_tls::backend_register_module(backend, windows_module));
#endif
}

static void unregister_tls_module(soinfo* si) {
  ScopedSignalBlocker ssb;
  ScopedWriteLock locker(&__libc_shared_globals()->tls_modules.rwlock);

  soinfo_tls* si_tls = si->get_tls();
  TlsModule& mod = g_tls_modules[__tls_module_id_to_idx(si_tls->module_id)];
  CHECK(mod.soinfo_ptr == si);
#if defined(_WIN32)
  q_tls::TlsBackend* backend = get_windows_tls_backend();
  CHECK(backend != nullptr);
  CHECK(q_tls::backend_unregister_module(backend, si_tls->module_id));
#endif
  mod = {};
  si_tls->module_id = kTlsUninitializedModuleId;
}

// The reference is valid until a TLS module is registered or unregistered.
const TlsModule& get_tls_module(size_t module_id) {
  size_t module_idx = __tls_module_id_to_idx(module_id);
  CHECK(module_idx < g_tls_modules.size());
  return g_tls_modules[module_idx];
}

extern "C" void __linker_reserve_bionic_tls_in_static_tls() {
  __libc_shared_globals()->static_tls_layout.reserve_bionic_tls();
}

void linker_setup_exe_static_tls(const char* progname) {
  soinfo* somain = solist_get_somain();
  StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
  if (somain->get_tls() == nullptr) {
    layout.reserve_exe_segment_and_tcb(nullptr, progname);
  } else {
    register_tls_module(somain, layout.reserve_exe_segment_and_tcb(&somain->get_tls()->segment, progname));
  }

  // The pthread key data is located at the very front of bionic_tls. As a
  // temporary workaround, allocate bionic_tls just after the thread pointer so
  // Golang can find its pthread key, as long as the executable's TLS segment is
  // small enough. Specifically, Golang scans forward 384 words from the TP on
  // ARM.
  //  - http://b/118381796
  //  - https://github.com/golang/go/issues/29674
  __linker_reserve_bionic_tls_in_static_tls();
}

void linker_finalize_static_tls() {
  g_static_tls_finished = true;
  __libc_shared_globals()->static_tls_layout.finish_layout();
}

void register_soinfo_tls(soinfo* si) {
#if defined(_WIN32)
  // The Apple Android libraries carry no PT_TLS of their own, yet their
  // initial-exec fs: accesses read the bionic TCB slots (errno, stack guard,
  // thread self, ...). The TCB must therefore exist and be published to the
  // Windows TLS backend even when no library contributes a TLS segment. The
  // standalone linker does this in linker_setup_exe_static_tls, which the
  // in-process hybris host never runs, so ensure it once here before the
  // no-TLS early return below. Guarded by offset_bionic_tcb(), so it runs once.
  {
    StaticTlsLayout& base_layout = __libc_shared_globals()->static_tls_layout;
    if (base_layout.offset_bionic_tcb() == SIZE_MAX) {
      base_layout.reserve_exe_segment_and_tcb(nullptr, nullptr);
      base_layout.reserve_bionic_tls();
      q_tls::TlsBackend* base_backend = get_windows_tls_backend();
      if (base_backend != nullptr) {
        q_tls::backend_set_static_layout(base_backend, base_layout.size(),
                                         base_layout.offset_thread_pointer());
      }
    }
  }
#endif
  soinfo_tls* si_tls = si->get_tls();
  if (si_tls == nullptr || si_tls->module_id != kTlsUninitializedModuleId) {
    return;
  }
  size_t static_offset = SIZE_MAX;
#if defined(_WIN32)
  // Windows cannot repurpose host FS/GS, so this is a synthetic guest layout.
  // It gives IE/LE relocations a stable offset and is backed by per-thread
  // storage in windows_tls_backend.cpp.
  StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
  if (layout.offset_bionic_tcb() == SIZE_MAX) {
    layout.reserve_exe_segment_and_tcb(nullptr, nullptr);
    layout.reserve_bionic_tls();
  }
  if (!g_static_tls_finished) {
    static_offset = layout.reserve_solib_segment(si_tls->segment);
  }
#else
  if (!g_static_tls_finished) {
    StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
    static_offset = layout.reserve_solib_segment(si_tls->segment);
  }
#endif
  register_tls_module(si, static_offset);
}

void unregister_soinfo_tls(soinfo* si) {
  soinfo_tls* si_tls = si->get_tls();
  if (si_tls == nullptr || si_tls->module_id == kTlsUninitializedModuleId) {
    return;
  }
  return unregister_tls_module(si);
}

#if defined(_WIN32)
q_tls::TlsContext* linker_tls_current_thread() {
  q_tls::TlsBackend* backend = get_windows_tls_backend();
  return backend == nullptr ? nullptr : q_tls::context_current(backend);
}

void** linker_tls_current_slots() {
  q_tls::TlsBackend* backend = get_windows_tls_backend();
  if (backend == nullptr) return nullptr;
  return q_tls::context_slots(q_tls::context_current_or_create(backend));
}

extern "C" void** __hybris_windows_get_tls() {
  return linker_tls_current_slots();
}

bool linker_tls_attach_current_thread() {
  q_tls::TlsBackend* backend = get_windows_tls_backend();
  if (backend == nullptr) return false;
  return q_tls::context_current_or_create(backend) != nullptr;
}

bool linker_tls_detach_current_thread() {
  q_tls::TlsBackend* backend = get_windows_tls_backend();
  if (backend == nullptr) return false;
  q_tls::TlsContext* context = q_tls::context_current(backend);
  if (context == nullptr) return false;
  if (!q_tls::context_detach(backend)) return false;
  return q_tls::context_destroy(context);
}

void* linker_tls_get_addr(const TlsIndex* index) {
  if (index == nullptr) return nullptr;
  q_tls::TlsBackend* backend = get_windows_tls_backend();
  if (backend == nullptr || q_tls::context_current_or_create(backend) == nullptr) {
    return nullptr;
  }
  const q_tls::TlsIndex windows_index = {index->module_id, index->offset};
  return q_tls::get_addr(backend, windows_index);
}

void* HYBRIS_SYSV_ABI linker_tls_get_static_addr(const TlsIndex* index) {
  if (index == nullptr) return nullptr;
  q_tls::TlsBackend* backend = get_windows_tls_backend();
  if (backend == nullptr || q_tls::context_current_or_create(backend) == nullptr) {
    return nullptr;
  }
  const q_tls::TlsIndex windows_index = {index->module_id, index->offset};
  return q_tls::get_static_addr(backend, windows_index);
}

void* HYBRIS_SYSV_ABI linker_tls_guest_thread_pointer() {
  q_tls::TlsBackend* backend = get_windows_tls_backend();
  return backend == nullptr ? nullptr : q_tls::guest_thread_pointer(backend);
}

void* HYBRIS_SYSV_ABI linker_tls_guest_addr(size_t module_id, int64_t tpoff) {
  q_tls::TlsBackend* backend = get_windows_tls_backend();
  if (backend == nullptr || q_tls::context_current_or_create(backend) == nullptr) return nullptr;
  const TlsModule& module = get_tls_module(module_id);
  const int64_t base = static_cast<int64_t>(module.static_offset) -
                       static_cast<int64_t>(__libc_shared_globals()->static_tls_layout.offset_thread_pointer());
  const int64_t offset = tpoff - base;
  if (offset < 0 || static_cast<size_t>(offset) >= module.segment.size) return nullptr;
  const q_tls::TlsIndex index = {module_id, static_cast<size_t>(offset)};
  return q_tls::get_static_addr(backend, index);
}
#endif
