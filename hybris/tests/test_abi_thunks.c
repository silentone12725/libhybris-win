/* SPDX-License-Identifier: MIT */
#include "hybris/common/abi_thunks.h"

#include <assert.h>
#include <math.h>

static int ctor_calls;
static int dtor_calls;

static void HYBRIS_ABI_SYSV ctor(int argc, char **argv, char **envp) {
    assert(argc == 2 && argv != 0 && envp != 0);
    ++ctor_calls;
}

static void HYBRIS_ABI_SYSV dtor(void) { ++dtor_calls; }
static uintptr_t HYBRIS_ABI_SYSV resolver(void) { return (uintptr_t)0x12345678; }

static double HYBRIS_ABI_MS ms_float64(double value, float factor) {
    return value * (double)factor;
}

static hybris_abi_float_pair HYBRIS_ABI_MS ms_float_pair(
    hybris_abi_float_pair value, double offset) {
    value.first += offset;
    value.second *= (float)offset;
    return value;
}

static double HYBRIS_ABI_SYSV sysv_float64(double value, float factor) {
    return value + (double)factor;
}

static hybris_abi_float_pair HYBRIS_ABI_SYSV sysv_float_pair(
    hybris_abi_float_pair value, double offset) {
    value.first -= offset;
    value.second += (float)offset;
    return value;
}

int main(void) {
    char *args[] = {(char *)"test", (char *)"arg", 0};
    char *env[] = {0};
    double scalar = 0.0;
    hybris_abi_float_pair input = {2.5, 3.0f};
    hybris_abi_float_pair output;
    uintptr_t resolved = 0;

    assert(hybris_abi_check_signature(HYBRIS_ABI_SIGNATURE_FLOAT64) == HYBRIS_ABI_STATUS_OK);
    assert(hybris_abi_check_signature(HYBRIS_ABI_SIGNATURE_FLOAT_PAIR) == HYBRIS_ABI_STATUS_OK);
    assert(hybris_abi_check_signature(HYBRIS_ABI_SIGNATURE_VARIADIC) ==
           HYBRIS_ABI_STATUS_UNSUPPORTED_VARIADIC);
    assert(hybris_abi_validate_function_address(0) == HYBRIS_ABI_STATUS_INVALID_ARGUMENT);
    assert(hybris_abi_validate_function_address(UINTPTR_MAX) == HYBRIS_ABI_STATUS_INVALID_ARGUMENT);
    assert(hybris_abi_call_sysv_ctor(ctor, 2, args, env) == HYBRIS_ABI_STATUS_OK);
    assert(hybris_abi_call_sysv_dtor(dtor) == HYBRIS_ABI_STATUS_OK);
    assert(hybris_abi_call_sysv_ctor(0, 0, 0, 0) == HYBRIS_ABI_STATUS_INVALID_ARGUMENT);
    assert(hybris_abi_call_sysv_dtor((hybris_abi_sysv_dtor_fn)(uintptr_t)-1) ==
           HYBRIS_ABI_STATUS_INVALID_ARGUMENT);
    assert(hybris_abi_call_sysv_ifunc0(resolver, &resolved) == HYBRIS_ABI_STATUS_OK);
    assert(resolved == (uintptr_t)0x12345678);
    assert(ctor_calls == 1 && dtor_calls == 1);

    assert(hybris_abi_call_ms_float64(ms_float64, 2.5, 4.0f, &scalar) == HYBRIS_ABI_STATUS_OK);
    assert(fabs(scalar - 10.0) < 0.00001);
    assert(hybris_abi_call_ms_float_pair(ms_float_pair, input, 4.0, &output) ==
           HYBRIS_ABI_STATUS_OK);
    assert(fabs(output.first - 6.5) < 0.00001 && fabsf(output.second - 12.0f) < 0.00001f);
    assert(hybris_abi_call_sysv_float64(sysv_float64, 2.5, 4.0f, &scalar) == HYBRIS_ABI_STATUS_OK);
    assert(fabs(scalar - 6.5) < 0.00001);
    assert(hybris_abi_call_sysv_float_pair(sysv_float_pair, input, 4.0, &output) ==
           HYBRIS_ABI_STATUS_OK);
    assert(fabs(output.first + 1.5) < 0.00001 && fabsf(output.second - 7.0f) < 0.00001f);
    assert(hybris_abi_call_ms_float64(ms_float64, 0, 0, 0) == HYBRIS_ABI_STATUS_INVALID_ARGUMENT);
    return 0;
}
