/*
 * Copyright (C) 2026
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef HYBRIS_COMMON_ABI_THUNKS_H_
#define HYBRIS_COMMON_ABI_THUNKS_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * GCC and Clang are the only compilers for which this layer can express both
 * x86-64 ABIs in a function type.  On other targets the annotations collapse
 * to the native ABI, and HYBRIS_ABI_HAS_CROSS_ABI is zero.  Keeping the macros
 * defined on every platform lets headers which describe an ELF entry point be
 * included by portable Linux code without compiler-specific conditionals.
 */
#if (defined(__GNUC__) || defined(__clang__)) && \
    (defined(__x86_64__) || defined(_M_X64))
#  define HYBRIS_ABI_SYSV __attribute__((sysv_abi))
#  define HYBRIS_ABI_MS   __attribute__((ms_abi))
#  define HYBRIS_ABI_HAS_CROSS_ABI 1
#else
#  define HYBRIS_ABI_SYSV
#  define HYBRIS_ABI_MS
#  define HYBRIS_ABI_HAS_CROSS_ABI 0
#endif

/* The layer intentionally has no untyped or variadic entry point. */
typedef enum hybris_abi_signature {
    HYBRIS_ABI_SIGNATURE_I64 = 1,
    HYBRIS_ABI_SIGNATURE_MIXED_I64 = 2,
    HYBRIS_ABI_SIGNATURE_PAIR_U64 = 3,
    HYBRIS_ABI_SIGNATURE_CALLBACK_I32 = 4,
    HYBRIS_ABI_SIGNATURE_VARIADIC = 0x100,
    HYBRIS_ABI_SIGNATURE_UNKNOWN = -1
} hybris_abi_signature;

typedef enum hybris_abi_status {
    HYBRIS_ABI_STATUS_OK = 0,
    HYBRIS_ABI_STATUS_INVALID_ARGUMENT = 1,
    HYBRIS_ABI_STATUS_UNSUPPORTED_PLATFORM = 2,
    HYBRIS_ABI_STATUS_UNSUPPORTED_SIGNATURE = 3,
    HYBRIS_ABI_STATUS_UNSUPPORTED_VARIADIC = 4
} hybris_abi_status;

typedef struct hybris_abi_pair_u64 {
    uint64_t lo;
    uint64_t hi;
} hybris_abi_pair_u64;

/* Every function-pointer type carries the ABI of its target explicitly. */
typedef int64_t (HYBRIS_ABI_SYSV *hybris_abi_sysv_i64_fn)(int64_t, int64_t);
typedef int64_t (HYBRIS_ABI_MS *hybris_abi_ms_i64_fn)(int64_t, int64_t);

typedef int64_t (HYBRIS_ABI_SYSV *hybris_abi_sysv_mixed_i64_fn)(
    int32_t, double, int64_t, float);
typedef int64_t (HYBRIS_ABI_MS *hybris_abi_ms_mixed_i64_fn)(
    int32_t, double, int64_t, float);

typedef hybris_abi_pair_u64 (HYBRIS_ABI_SYSV *hybris_abi_sysv_pair_u64_fn)(
    uint64_t, uint64_t);
typedef hybris_abi_pair_u64 (HYBRIS_ABI_MS *hybris_abi_ms_pair_u64_fn)(
    uint64_t, uint64_t);

typedef int32_t (HYBRIS_ABI_SYSV *hybris_abi_sysv_callback_i32_fn)(
    int32_t, double);
typedef int32_t (HYBRIS_ABI_MS *hybris_abi_ms_callback_i32_fn)(
    int32_t, double);

/* ELF lifecycle entry points use the SysV ABI on the Windows host. */
typedef void (HYBRIS_ABI_SYSV *hybris_abi_sysv_ctor_fn)(int, char **, char **);
typedef void (HYBRIS_ABI_SYSV *hybris_abi_sysv_dtor_fn)(void);
typedef uintptr_t (HYBRIS_ABI_SYSV *hybris_abi_sysv_ifunc0_fn)(void);

/* Validate the closed signature set before resolving an ELF entry point. */
hybris_abi_status hybris_abi_check_signature(hybris_abi_signature signature);

hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_sysv_ctor(
    hybris_abi_sysv_ctor_fn function, int argc, char **argv, char **envp);
hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_sysv_dtor(hybris_abi_sysv_dtor_fn function);
hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_sysv_ifunc0(
    hybris_abi_sysv_ifunc0_fn function, uintptr_t *result);

/* A SysV caller invoking a Microsoft-ABI target. */
hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_ms_i64(
    hybris_abi_ms_i64_fn function, int64_t left, int64_t right, int64_t *result);
hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_ms_mixed_i64(
    hybris_abi_ms_mixed_i64_fn function, int32_t integer, double real,
    int64_t wide_integer, float single, int64_t *result);
hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_ms_pair_u64(
    hybris_abi_ms_pair_u64_fn function, uint64_t left, uint64_t right,
    hybris_abi_pair_u64 *result);
hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_ms_callback_i32(
    hybris_abi_ms_callback_i32_fn callback, int32_t value, double factor,
    int32_t *result);

/* A Microsoft-ABI caller invoking a SysV target. */
hybris_abi_status HYBRIS_ABI_MS hybris_abi_call_sysv_i64(
    hybris_abi_sysv_i64_fn function, int64_t left, int64_t right, int64_t *result);
hybris_abi_status HYBRIS_ABI_MS hybris_abi_call_sysv_mixed_i64(
    hybris_abi_sysv_mixed_i64_fn function, int32_t integer, double real,
    int64_t wide_integer, float single, int64_t *result);
hybris_abi_status HYBRIS_ABI_MS hybris_abi_call_sysv_pair_u64(
    hybris_abi_sysv_pair_u64_fn function, uint64_t left, uint64_t right,
    hybris_abi_pair_u64 *result);
hybris_abi_status HYBRIS_ABI_MS hybris_abi_call_sysv_callback_i32(
    hybris_abi_sysv_callback_i32_fn callback, int32_t value, double factor,
    int32_t *result);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* HYBRIS_COMMON_ABI_THUNKS_H_ */
