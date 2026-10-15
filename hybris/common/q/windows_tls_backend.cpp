/*
 * Copyright (C) 2026 The libhybris developers
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "windows_tls_backend.h"

#include <atomic>
#include <cstring>
#include <map>
#include <mutex>

#if defined(_WIN32)
#include <windows.h>
#include <malloc.h>
#else
#include <pthread.h>
#include <stdlib.h>
#endif

namespace q_tls {

struct TlsContext;

namespace {

struct Module {
  const void* init_ptr;
  size_t init_size;
  size_t size;
  size_t alignment;
  TlsDestructor destructor;
  size_t generation;
};

struct Allocation {
  void* block;
  size_t size;
  TlsDestructor destructor;
  size_t generation;
};

void free_block(Allocation* allocation) {
  if (allocation->block == nullptr) return;
  if (allocation->destructor != nullptr) {
    allocation->destructor(allocation->block, allocation->size);
  }
#if defined(_WIN32)
  _aligned_free(allocation->block);
#else
  free(allocation->block);
#endif
  allocation->block = nullptr;
}

void cleanup_context(TlsContext* context);

#if defined(_WIN32)
void CALLBACK fls_cleanup(void* value);
#else
void pthread_cleanup(void* value);
#endif

}  // namespace

struct TlsBackend {
  std::mutex modules_lock;
  std::map<size_t, Module> modules;
  size_t next_generation;
  std::atomic<size_t> context_count;
#if defined(_WIN32)
  DWORD fls_index;
#else
  pthread_key_t pthread_key;
#endif

  TlsBackend()
      : next_generation(0), context_count(0)
#if defined(_WIN32)
        , fls_index(FLS_OUT_OF_INDEXES)
#endif
  {}
};

struct TlsContext {
  explicit TlsContext(TlsBackend* owner) : backend(owner), attached(false), auto_destroy(false) {
    std::memset(bionic_slots, 0, sizeof(bionic_slots));
  }

  TlsBackend* backend;
  bool attached;
  bool auto_destroy;
  void* bionic_slots[16];
  std::mutex allocations_lock;
  std::map<size_t, Allocation> allocations;
};

namespace {

#if defined(_WIN32)
void CALLBACK fls_cleanup(void* value) {
  if (value == nullptr) return;
  TlsContext* context = static_cast<TlsContext*>(value);
  TlsBackend* backend = context->backend;
  const bool auto_destroy = context->auto_destroy;
  cleanup_context(context);
  if (auto_destroy && backend != nullptr) {
    context->backend = nullptr;
    backend->context_count.fetch_sub(1);
    delete context;
  }
}
#else
void pthread_cleanup(void* value) {
  if (value == nullptr) return;
  TlsContext* context = static_cast<TlsContext*>(value);
  TlsBackend* backend = context->backend;
  const bool auto_destroy = context->auto_destroy;
  cleanup_context(context);
  if (auto_destroy && backend != nullptr) {
    context->backend = nullptr;
    backend->context_count.fetch_sub(1);
    delete context;
  }
}
#endif

void cleanup_context(TlsContext* context) {
  std::lock_guard<std::mutex> lock(context->allocations_lock);
  for (std::map<size_t, Allocation>::iterator it = context->allocations.begin();
       it != context->allocations.end(); ++it) {
    free_block(&it->second);
  }
  context->allocations.clear();
  context->attached = false;
}

bool valid_alignment(size_t alignment) {
  return alignment != 0 && (alignment & (alignment - 1)) == 0;
}

void* allocate_block(size_t size, size_t alignment) {
  const size_t allocation_size = size == 0 ? 1 : size;
  const size_t allocation_alignment = alignment < sizeof(void*) ? sizeof(void*) : alignment;
#if defined(_WIN32)
  return _aligned_malloc(allocation_size, allocation_alignment);
#else
  void* block = nullptr;
  if (posix_memalign(&block, allocation_alignment, allocation_size) != 0) return nullptr;
  return block;
#endif
}

bool current_value(TlsBackend* backend, TlsContext** context) {
#if defined(_WIN32)
  *context = static_cast<TlsContext*>(FlsGetValue(backend->fls_index));
  return true;
#else
  *context = static_cast<TlsContext*>(pthread_getspecific(backend->pthread_key));
  return true;
#endif
}

bool set_current(TlsBackend* backend, TlsContext* context) {
#if defined(_WIN32)
  return FlsSetValue(backend->fls_index, context) != FALSE;
#else
  return pthread_setspecific(backend->pthread_key, context) == 0;
#endif
}

}  // namespace

TlsBackend* backend_create() {
  TlsBackend* backend = new TlsBackend();
#if defined(_WIN32)
  backend->fls_index = FlsAlloc(fls_cleanup);
  if (backend->fls_index == FLS_OUT_OF_INDEXES) {
    delete backend;
    return nullptr;
  }
#else
  if (pthread_key_create(&backend->pthread_key, pthread_cleanup) != 0) {
    delete backend;
    return nullptr;
  }
#endif
  return backend;
}

bool backend_destroy(TlsBackend* backend) {
  if (backend == nullptr || backend->context_count.load() != 0) return false;
#if defined(_WIN32)
  if (backend->fls_index != FLS_OUT_OF_INDEXES) {
    if (!FlsFree(backend->fls_index)) return false;
    backend->fls_index = FLS_OUT_OF_INDEXES;
  }
#else
  if (pthread_key_delete(backend->pthread_key) != 0) return false;
#endif
  delete backend;
  return true;
}

bool backend_register_module(TlsBackend* backend, const TlsModule& module) {
  if (backend == nullptr || module.module_id == 0 || !valid_alignment(module.alignment) ||
      module.init_size > module.size || (module.init_size != 0 && module.init_ptr == nullptr)) {
    return false;
  }

  std::lock_guard<std::mutex> lock(backend->modules_lock);
  if (backend->modules.find(module.module_id) != backend->modules.end()) return false;
  ++backend->next_generation;
  if (backend->next_generation == 0) ++backend->next_generation;
  backend->modules.insert(std::make_pair(
      module.module_id,
      Module{module.init_ptr, module.init_size, module.size, module.alignment, module.destructor,
             backend->next_generation}));
  return true;
}

bool backend_unregister_module(TlsBackend* backend, size_t module_id) {
  if (backend == nullptr || module_id == 0) return false;
  std::lock_guard<std::mutex> lock(backend->modules_lock);
  return backend->modules.erase(module_id) == 1;
}

TlsContext* context_create(TlsBackend* backend) {
  if (backend == nullptr) return nullptr;
  TlsContext* context = new TlsContext(backend);
  backend->context_count.fetch_add(1);
  return context;
}

TlsContext* context_current_or_create(TlsBackend* backend) {
  if (backend == nullptr) return nullptr;

  TlsContext* current = nullptr;
  if (!current_value(backend, &current)) return nullptr;
  if (current != nullptr && current->backend == backend && current->attached) {
    return current;
  }
  if (current != nullptr) return nullptr;

  TlsContext* context = context_create(backend);
  if (context == nullptr) return nullptr;
  context->auto_destroy = true;
  if (!set_current(backend, context)) {
    context->auto_destroy = false;
    context_destroy(context);
    return nullptr;
  }
  context->attached = true;
  return context;
}

void** context_slots(TlsContext* context) {
  return context == nullptr ? nullptr : context->bionic_slots;
}

bool context_destroy(TlsContext* context) {
  if (context == nullptr || context->attached) return false;
  TlsBackend* backend = context->backend;
  if (backend == nullptr) return false;
  cleanup_context(context);
  context->backend = nullptr;
  backend->context_count.fetch_sub(1);
  delete context;
  return true;
}

bool context_attach(TlsBackend* backend, TlsContext* context) {
  if (backend == nullptr || context == nullptr || context->backend != backend || context->attached) {
    return false;
  }

  TlsContext* current = nullptr;
  if (!current_value(backend, &current) || (current != nullptr && current != context)) return false;
  if (!set_current(backend, context)) return false;
  context->attached = true;
  return true;
}

TlsContext* context_current(TlsBackend* backend) {
  if (backend == nullptr) return nullptr;
  TlsContext* context = nullptr;
  if (!current_value(backend, &context) || context == nullptr || context->backend != backend ||
      !context->attached) {
    return nullptr;
  }
  return context;
}

bool context_detach(TlsBackend* backend) {
  if (backend == nullptr) return false;
  TlsContext* context = context_current(backend);
  if (context == nullptr) return false;
  if (!set_current(backend, nullptr)) return false;
  cleanup_context(context);
  return true;
}

void* get_addr(TlsBackend* backend, const TlsIndex& index) {
  TlsContext* context = context_current(backend);
  if (context == nullptr || index.module_id == 0) return nullptr;

  Module module = {};
  {
    std::lock_guard<std::mutex> lock(backend->modules_lock);
    std::map<size_t, Module>::const_iterator it = backend->modules.find(index.module_id);
    if (it == backend->modules.end()) return nullptr;
    module = it->second;
  }

  if (module.size != 0 && index.offset >= module.size) return nullptr;
  if (module.size == 0 && index.offset != 0) return nullptr;

  std::lock_guard<std::mutex> lock(context->allocations_lock);
  std::map<size_t, Allocation>::iterator it = context->allocations.find(index.module_id);
  if (it != context->allocations.end() && it->second.generation != module.generation) {
    free_block(&it->second);
    context->allocations.erase(it);
    it = context->allocations.end();
  }
  if (it == context->allocations.end()) {
    void* block = allocate_block(module.size, module.alignment);
    if (block == nullptr) return nullptr;
    if (module.init_size != 0) std::memcpy(block, module.init_ptr, module.init_size);
    if (module.size > module.init_size) {
      std::memset(static_cast<char*>(block) + module.init_size, 0, module.size - module.init_size);
    }
    Allocation allocation = {block, module.size, module.destructor, module.generation};
    it = context->allocations.insert(std::make_pair(index.module_id, allocation)).first;
  }

  return static_cast<char*>(it->second.block) + index.offset;
}

}  // namespace q_tls
