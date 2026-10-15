/*
 * Copyright (C) 2026
 *
 * SPDX-License-Identifier: MIT
 */

#include "hybris/common/abi_thunks.h"

static hybris_abi_status validate_result(const void *result) {
    if (result == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
#if !HYBRIS_ABI_HAS_CROSS_ABI
    return HYBRIS_ABI_STATUS_UNSUPPORTED_PLATFORM;
#else
    return HYBRIS_ABI_STATUS_OK;
#endif
}

hybris_abi_status hybris_abi_check_signature(hybris_abi_signature signature) {
    switch (signature) {
    case HYBRIS_ABI_SIGNATURE_I64:
    case HYBRIS_ABI_SIGNATURE_MIXED_I64:
    case HYBRIS_ABI_SIGNATURE_PAIR_U64:
    case HYBRIS_ABI_SIGNATURE_CALLBACK_I32:
        return HYBRIS_ABI_STATUS_OK;
    case HYBRIS_ABI_SIGNATURE_VARIADIC:
        return HYBRIS_ABI_STATUS_UNSUPPORTED_VARIADIC;
    case HYBRIS_ABI_SIGNATURE_UNKNOWN:
    default:
        return HYBRIS_ABI_STATUS_UNSUPPORTED_SIGNATURE;
    }
}

hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_sysv_ctor(
    hybris_abi_sysv_ctor_fn function, int argc, char **argv, char **envp) {
    if (function == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
    function(argc, argv, envp);
    return HYBRIS_ABI_STATUS_OK;
}

hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_sysv_dtor(
    hybris_abi_sysv_dtor_fn function) {
    if (function == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
    function();
    return HYBRIS_ABI_STATUS_OK;
}

hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_sysv_ifunc0(
    hybris_abi_sysv_ifunc0_fn function, uintptr_t *result) {
    if (function == 0 || result == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
    *result = function();
    return HYBRIS_ABI_STATUS_OK;
}

hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_ms_i64(
    hybris_abi_ms_i64_fn function, int64_t left, int64_t right, int64_t *result) {
    hybris_abi_status status;
    if (function == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
    status = validate_result(result);
    if (status != HYBRIS_ABI_STATUS_OK) {
        return status;
    }
    *result = function(left, right);
    return HYBRIS_ABI_STATUS_OK;
}

hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_ms_mixed_i64(
    hybris_abi_ms_mixed_i64_fn function, int32_t integer, double real,
    int64_t wide_integer, float single, int64_t *result) {
    hybris_abi_status status;
    if (function == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
    status = validate_result(result);
    if (status != HYBRIS_ABI_STATUS_OK) {
        return status;
    }
    *result = function(integer, real, wide_integer, single);
    return HYBRIS_ABI_STATUS_OK;
}

hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_ms_pair_u64(
    hybris_abi_ms_pair_u64_fn function, uint64_t left, uint64_t right,
    hybris_abi_pair_u64 *result) {
    hybris_abi_status status;
    if (function == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
    status = validate_result(result);
    if (status != HYBRIS_ABI_STATUS_OK) {
        return status;
    }
    *result = function(left, right);
    return HYBRIS_ABI_STATUS_OK;
}

hybris_abi_status HYBRIS_ABI_SYSV hybris_abi_call_ms_callback_i32(
    hybris_abi_ms_callback_i32_fn callback, int32_t value, double factor,
    int32_t *result) {
    hybris_abi_status status;
    if (callback == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
    status = validate_result(result);
    if (status != HYBRIS_ABI_STATUS_OK) {
        return status;
    }
    *result = callback(value, factor);
    return HYBRIS_ABI_STATUS_OK;
}

hybris_abi_status HYBRIS_ABI_MS hybris_abi_call_sysv_i64(
    hybris_abi_sysv_i64_fn function, int64_t left, int64_t right, int64_t *result) {
    hybris_abi_status status;
    if (function == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
    status = validate_result(result);
    if (status != HYBRIS_ABI_STATUS_OK) {
        return status;
    }
    *result = function(left, right);
    return HYBRIS_ABI_STATUS_OK;
}

hybris_abi_status HYBRIS_ABI_MS hybris_abi_call_sysv_mixed_i64(
    hybris_abi_sysv_mixed_i64_fn function, int32_t integer, double real,
    int64_t wide_integer, float single, int64_t *result) {
    hybris_abi_status status;
    if (function == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
    status = validate_result(result);
    if (status != HYBRIS_ABI_STATUS_OK) {
        return status;
    }
    *result = function(integer, real, wide_integer, single);
    return HYBRIS_ABI_STATUS_OK;
}

hybris_abi_status HYBRIS_ABI_MS hybris_abi_call_sysv_pair_u64(
    hybris_abi_sysv_pair_u64_fn function, uint64_t left, uint64_t right,
    hybris_abi_pair_u64 *result) {
    hybris_abi_status status;
    if (function == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
    status = validate_result(result);
    if (status != HYBRIS_ABI_STATUS_OK) {
        return status;
    }
    *result = function(left, right);
    return HYBRIS_ABI_STATUS_OK;
}

hybris_abi_status HYBRIS_ABI_MS hybris_abi_call_sysv_callback_i32(
    hybris_abi_sysv_callback_i32_fn callback, int32_t value, double factor,
    int32_t *result) {
    hybris_abi_status status;
    if (callback == 0) {
        return HYBRIS_ABI_STATUS_INVALID_ARGUMENT;
    }
    status = validate_result(result);
    if (status != HYBRIS_ABI_STATUS_OK) {
        return status;
    }
    *result = callback(value, factor);
    return HYBRIS_ABI_STATUS_OK;
}
