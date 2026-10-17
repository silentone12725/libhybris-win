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
#include <climits>

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
  size_t static_offset;
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

struct StaticAllocation {
  void* block;
  size_t size;
};

void free_block(Allocation* allocation) {
  if (allocation->block == nullptr) return;
  void* block = allocation->block;
  const size_t size = allocation->size;
  const TlsDestructor destructor = allocation->destructor;
  allocation->block = nullptr;
  allocation->size = 0;
  allocation->destructor = nullptr;
  allocation->generation = 0;
  if (destructor != nullptr) destructor(block, size);
#if defined(_WIN32)
  _aligned_free(block);
#else
  free(block);
#endif
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
  size_t static_size;
  size_t static_tp_offset;
#if defined(_WIN32)
  DWORD fls_index;
#else
  pthread_key_t pthread_key;
#endif

  TlsBackend()
      : next_generation(0), context_count(0), static_size(0), static_tp_offset(SIZE_MAX)
#if defined(_WIN32)
        , fls_index(FLS_OUT_OF_INDEXES)
#endif
  {}
};

struct TlsContext {
  explicit TlsContext(TlsBackend* owner) : backend(owner), attached(false), auto_destroy(false) {
    std::memset(bionic_slots, 0, sizeof(bionic_slots));
    static_allocation = {nullptr, 0};
  }

  TlsBackend* backend;
  bool attached;
  bool auto_destroy;
  void* bionic_slots[16];
  std::mutex allocations_lock;
  std::map<size_t, Allocation> allocations;
  StaticAllocation static_allocation;
};

namespace {

#if defined(_WIN32)
void CALLBACK fls_cleanup(void* value) {
  if (value == nullptr) return;
  TlsContext* context = static_cast<TlsContext*>(value);
  TlsBackend* backend = context->backend;
  const bool auto_destroy = context->auto_destroy;
  if (backend != nullptr) FlsSetValue(backend->fls_index, nullptr);
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
  if (backend != nullptr) pthread_setspecific(backend->pthread_key, nullptr);
  cleanup_context(context);
  if (auto_destroy && backend != nullptr) {
    context->backend = nullptr;
    backend->context_count.fetch_sub(1);
    delete context;
  }
}
#endif

void cleanup_context(TlsContext* context) {
  std::map<size_t, Allocation> allocations;
  {
    std::lock_guard<std::mutex> lock(context->allocations_lock);
    allocations.swap(context->allocations);
    context->attached = false;
  }
  for (std::map<size_t, Allocation>::iterator it = allocations.begin(); it != allocations.end();
       ++it) {
    free_block(&it->second);
  }
  if (context->static_allocation.block != nullptr) {
#if defined(_WIN32)
    _aligned_free(context->static_allocation.block);
#else
    free(context->static_allocation.block);
#endif
    context->static_allocation = {nullptr, 0};
  }
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
       module.init_size > module.size || (module.init_size != 0 && module.init_ptr == nullptr) ||
       (module.static_offset != SIZE_MAX && module.static_offset > SIZE_MAX - module.size)) {
    return false;
  }

  std::lock_guard<std::mutex> lock(backend->modules_lock);
  if (backend->modules.find(module.module_id) != backend->modules.end()) return false;
  ++backend->next_generation;
  if (backend->next_generation == 0) ++backend->next_generation;
  backend->modules.insert(std::make_pair(
      module.module_id,
       Module{module.static_offset, module.init_ptr, module.init_size, module.size, module.alignment,
              module.destructor,
              backend->next_generation}));
  return true;
}

bool backend_set_static_layout(TlsBackend* backend, size_t size, size_t tp_offset) {
  if (backend == nullptr || tp_offset > size) return false;
  std::lock_guard<std::mutex> lock(backend->modules_lock);
  if (size < backend->static_size) return false;
  backend->static_size = size;
  backend->static_tp_offset = tp_offset;
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

  for (;;) {
    Allocation stale = {};
    bool static_module = false;
    {
      std::lock_guard<std::mutex> modules_lock(backend->modules_lock);
      std::map<size_t, Module>::const_iterator module_it =
          backend->modules.find(index.module_id);
      if (module_it == backend->modules.end()) return nullptr;
      const Module& module = module_it->second;
      if ((module.size != 0 && index.offset >= module.size) ||
          (module.size == 0 && index.offset != 0)) return nullptr;
      static_module = module.static_offset != SIZE_MAX;
      if (!static_module) {
        std::lock_guard<std::mutex> allocations_lock(context->allocations_lock);
        std::map<size_t, Allocation>::iterator it = context->allocations.find(index.module_id);
        if (it != context->allocations.end() && it->second.generation == module.generation) {
          return static_cast<char*>(it->second.block) + index.offset;
        }
        if (it != context->allocations.end()) {
          stale = it->second;
          context->allocations.erase(it);
        } else {
          void* block = allocate_block(module.size, module.alignment);
          if (block == nullptr) return nullptr;
          if (module.init_size != 0) std::memcpy(block, module.init_ptr, module.init_size);
          if (module.size > module.init_size) {
            std::memset(static_cast<char*>(block) + module.init_size, 0,
                        module.size - module.init_size);
          }
          Allocation allocation = {block, module.size, module.destructor, module.generation};
          it = context->allocations.insert(std::make_pair(index.module_id, allocation)).first;
          return static_cast<char*>(it->second.block) + index.offset;
        }
      }
    }
    if (static_module) return get_static_addr(backend, index);

    // Destructors may call back into the backend, so never run one while
    // holding either backend or context locks.
    free_block(&stale);
  }
}

namespace {

bool ensure_static_block(TlsBackend* backend, TlsContext* context) {
  std::lock_guard<std::mutex> modules_lock(backend->modules_lock);
  if (backend->static_tp_offset == SIZE_MAX) return false;
  const size_t required = backend->static_size == 0 ? 1 : backend->static_size;
  if (context->static_allocation.size >= required) return true;

  void* replacement = allocate_block(required, alignof(max_align_t));
  if (replacement == nullptr) return false;
  std::memset(replacement, 0, required);
  if (context->static_allocation.block != nullptr) {
    std::memcpy(replacement, context->static_allocation.block, context->static_allocation.size);
#if defined(_WIN32)
    _aligned_free(context->static_allocation.block);
#else
    free(context->static_allocation.block);
#endif
  }

  const size_t old_size = context->static_allocation.size;
  context->static_allocation = {replacement, required};
  for (std::map<size_t, Module>::const_iterator it = backend->modules.begin();
       it != backend->modules.end(); ++it) {
    const Module& module = it->second;
    if (module.static_offset == SIZE_MAX || module.init_size == 0 ||
        module.static_offset >= old_size) {
      if (module.static_offset != SIZE_MAX && module.init_size != 0) {
        std::memcpy(static_cast<char*>(replacement) + module.static_offset,
                    module.init_ptr, module.init_size);
      }
    }
  }
  return true;
}

}  // namespace

void* get_static_addr(TlsBackend* backend, const TlsIndex& index) {
  if (backend == nullptr || index.module_id == 0) return nullptr;
  TlsContext* context = context_current(backend);
  if (context == nullptr) return nullptr;
  std::lock_guard<std::mutex> lock(context->allocations_lock);
  if (!ensure_static_block(backend, context)) return nullptr;
  std::lock_guard<std::mutex> modules_lock(backend->modules_lock);
  std::map<size_t, Module>::const_iterator it = backend->modules.find(index.module_id);
  if (it == backend->modules.end() || it->second.static_offset == SIZE_MAX ||
      index.offset > it->second.size ||
       (it->second.size != 0 && index.offset >= it->second.size) ||
       (it->second.size == 0 && index.offset != 0) ||
       it->second.static_offset > backend->static_size - index.offset) return nullptr;
  return static_cast<char*>(context->static_allocation.block) + it->second.static_offset +
         index.offset;
}

void* guest_thread_pointer(TlsBackend* backend) {
  if (backend == nullptr) return nullptr;
  TlsContext* context = context_current_or_create(backend);
  if (context == nullptr) return nullptr;
  std::lock_guard<std::mutex> lock(context->allocations_lock);
  if (!ensure_static_block(backend, context)) return nullptr;
  return static_cast<char*>(context->static_allocation.block) + backend->static_tp_offset;
}

}  // namespace q_tls
