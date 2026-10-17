/* SPDX-License-Identifier: MIT */
#include "hybris/common/abi_thunks.h"

#include <assert.h>
#include <math.h>

static int ctor_calls;
static int dtor_calls;
static int ms_callback_calls;
static int sysv_callback_calls;

static void HYBRIS_ABI_SYSV ctor(int argc, char **argv, char **envp) {
    assert(argc == 2 && argv != 0 && envp != 0);
    ++ctor_calls;
}

static void HYBRIS_ABI_SYSV dtor(void) { ++dtor_calls; }
static uintptr_t HYBRIS_ABI_SYSV resolver(void) { return (uintptr_t)0x12345678; }

static int64_t mixed_result(int32_t integer, double real, int64_t wide_integer,
                            float single) {
    return wide_integer + (int64_t)integer * INT64_C(1000000) +
           (int64_t)(real * 100.0) + (int64_t)(single * 10.0f);
}

static int64_t HYBRIS_ABI_MS ms_mixed_i64(
    int32_t integer, double real, int64_t wide_integer, float single) {
    return mixed_result(integer, real, wide_integer, single);
}

static int64_t HYBRIS_ABI_SYSV sysv_mixed_i64(
    int32_t integer, double real, int64_t wide_integer, float single) {
    return mixed_result(integer, real, wide_integer, single);
}

static hybris_abi_pair_u64 HYBRIS_ABI_MS ms_pair_u64(uint64_t left, uint64_t right) {
    hybris_abi_pair_u64 result = {left ^ UINT64_C(0xfeedfacecafebeef),
                                  right + UINT64_C(0x1020304050607080)};
    return result;
}

static hybris_abi_pair_u64 HYBRIS_ABI_SYSV sysv_pair_u64(uint64_t left, uint64_t right) {
    hybris_abi_pair_u64 result = {left ^ UINT64_C(0xfeedfacecafebeef),
                                  right + UINT64_C(0x1020304050607080)};
    return result;
}

static int32_t HYBRIS_ABI_MS ms_callback_i32(int32_t value, double factor) {
    ++ms_callback_calls;
    return value + (int32_t)(factor * 10.0);
}

static int32_t HYBRIS_ABI_SYSV sysv_callback_i32(int32_t value, double factor) {
    ++sysv_callback_calls;
    return value + (int32_t)(factor * 10.0);
}

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

static int32_t exercise_ms_callback_lifetime(void) {
    hybris_abi_ms_callback_i32_fn callback = ms_callback_i32;
    int32_t result = 0;

    for (int32_t value = 1; value <= 32; ++value) {
        assert(hybris_abi_call_ms_callback_i32(callback, value, 2.5, &result) ==
               HYBRIS_ABI_STATUS_OK);
        assert(result == value + 25);
    }
    return result;
}

static int32_t exercise_sysv_callback_lifetime(void) {
    hybris_abi_sysv_callback_i32_fn callback = sysv_callback_i32;
    int32_t result = 0;

    for (int32_t value = 1; value <= 32; ++value) {
        assert(hybris_abi_call_sysv_callback_i32(callback, value, 2.5, &result) ==
               HYBRIS_ABI_STATUS_OK);
        assert(result == value + 25);
    }
    return result;
}

static void test_stack_preservation(void) {
    volatile uint64_t before = UINT64_C(0x0123456789abcdef);
    volatile uint64_t after = UINT64_C(0xfedcba9876543210);
    int64_t scalar = 0;
    hybris_abi_pair_u64 pair = {0, 0};

    for (int i = 0; i < 32; ++i) {
        assert(hybris_abi_call_ms_mixed_i64(
                   ms_mixed_i64, -17, 2.5, INT64_C(0x1122334455667788), 3.5f, &scalar) ==
               HYBRIS_ABI_STATUS_OK);
        assert(hybris_abi_call_sysv_mixed_i64(
                   sysv_mixed_i64, 17, -2.5, INT64_C(0x8877665544332211), -3.5f, &scalar) ==
               HYBRIS_ABI_STATUS_OK);
        assert(hybris_abi_call_ms_pair_u64(ms_pair_u64, UINT64_C(0x1111222233334444),
                                           UINT64_C(0x5555666677778888), &pair) ==
               HYBRIS_ABI_STATUS_OK);
        assert(hybris_abi_call_sysv_pair_u64(sysv_pair_u64, UINT64_C(0x9999aaaabbbbcccc),
                                             UINT64_C(0xddddeeeeffff0000), &pair) ==
               HYBRIS_ABI_STATUS_OK);
        assert(before == UINT64_C(0x0123456789abcdef));
        assert(after == UINT64_C(0xfedcba9876543210));
    }
}

int main(void) {
    char *args[] = {(char *)"test", (char *)"arg", 0};
    char *env[] = {0};
    double scalar = 0.0;
    hybris_abi_float_pair input = {2.5, 3.0f};
    hybris_abi_float_pair output;
    hybris_abi_pair_u64 pair;
    int64_t mixed = 0;
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

    assert(hybris_abi_call_ms_mixed_i64(ms_mixed_i64, -17, 2.5,
                                       INT64_C(0x1122334455667788), 3.5f, &mixed) ==
           HYBRIS_ABI_STATUS_OK);
    assert(mixed == mixed_result(-17, 2.5, INT64_C(0x1122334455667788), 3.5f));
    assert(hybris_abi_call_sysv_mixed_i64(sysv_mixed_i64, 17, -2.5,
                                         INT64_C(0x8877665544332211), -3.5f, &mixed) ==
           HYBRIS_ABI_STATUS_OK);
    assert(mixed == mixed_result(17, -2.5, INT64_C(0x8877665544332211), -3.5f));

    assert(hybris_abi_call_ms_pair_u64(ms_pair_u64, UINT64_C(0x1111222233334444),
                                       UINT64_C(0x5555666677778888), &pair) ==
           HYBRIS_ABI_STATUS_OK);
    assert(pair.lo == (UINT64_C(0x1111222233334444) ^ UINT64_C(0xfeedfacecafebeef)) &&
           pair.hi == UINT64_C(0x657596a6c7d7f908));
    assert(hybris_abi_call_sysv_pair_u64(sysv_pair_u64, UINT64_C(0x9999aaaabbbbcccc),
                                         UINT64_C(0xddddeeeeffff0000), &pair) ==
           HYBRIS_ABI_STATUS_OK);
    assert(pair.lo == (UINT64_C(0x9999aaaabbbbcccc) ^ UINT64_C(0xfeedfacecafebeef)) &&
           pair.hi == UINT64_C(0xedfe1f2f505f7080));

    assert(exercise_ms_callback_lifetime() == 57);
    assert(exercise_sysv_callback_lifetime() == 57);
    assert(ms_callback_calls == 32 && sysv_callback_calls == 32);
    test_stack_preservation();

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
