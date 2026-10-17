/*
 * Copyright (C) 2026 The libhybris developers
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include <stddef.h>

namespace q_tls {

// This is the subset of an ELF PT_TLS description needed by the Windows
// backend. init_ptr points into the already-loaded ELF image and therefore
// must remain valid while the module is registered.
typedef void (*TlsDestructor)(void* block, size_t size);

struct TlsModule {
  size_t module_id;
  // SIZE_MAX means that this module uses the dynamic allocation path.  Static
  // modules are placed in the synthetic guest TLS block at this offset.
  size_t static_offset;
  const void* init_ptr;
  size_t init_size;
  size_t size;
  size_t alignment;
  TlsDestructor destructor;
};

// The fields intentionally match the dynamic TLS lookup used by the Q
// linker: module_id is the ELF module ID and offset is relative to that
// module's TLS block.
struct TlsIndex {
  size_t module_id;
  size_t offset;
};

struct TlsBackend;
struct TlsContext;

TlsBackend* backend_create();

// Configure the synthetic guest TLS address space.  This is deliberately
// independent of the host FS/GS bases; guest code that needs a thread pointer
// is rewritten to use the accessors below.
bool backend_set_static_layout(TlsBackend* backend, size_t size, size_t tp_offset);

// Returns false when a context still exists. Callers must detach and destroy
// every context before destroying its backend.
bool backend_destroy(TlsBackend* backend);

bool backend_register_module(TlsBackend* backend, const TlsModule& module);
bool backend_unregister_module(TlsBackend* backend, size_t module_id);

TlsContext* context_create(TlsBackend* backend);
bool context_destroy(TlsContext* context);

// Returns the context already associated with this thread, or creates an
// owned context and associates it with the thread. Owned contexts are
// released by the FLS/pthread-key cleanup callback at thread exit.
TlsContext* context_current_or_create(TlsBackend* backend);

// Returns the Bionic-compatible per-context slot storage. The storage is
// owned by the context and remains valid until that context is destroyed.
void** context_slots(TlsContext* context);

// A context is explicitly owned by its caller. It may be attached to one
// thread at a time. On Windows the attachment is stored with FlsSetValue;
// no TEB layout or segment-register access is used.
bool context_attach(TlsBackend* backend, TlsContext* context);
TlsContext* context_current(TlsBackend* backend);
bool context_detach(TlsBackend* backend);

// Returns the current thread's address for a dynamic TLS index, allocating and
// initializing that module's block on first use. Returns nullptr for an
// unknown module, an unattached thread, or an out-of-range offset.
void* get_addr(TlsBackend* backend, const TlsIndex& index);

void* get_static_addr(TlsBackend* backend, const TlsIndex& index);
void* guest_thread_pointer(TlsBackend* backend);

}  // namespace q_tls
