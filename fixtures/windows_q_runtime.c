#include <stdint.h>

extern int hybris_fixture_dependency_value(void);

static int constructor_ran;
static int destructor_ran;
__thread int hybris_fixture_tls;

__attribute__((constructor)) static void fixture_constructor(void) {
    constructor_ran = 1;
}

__attribute__((destructor)) static void fixture_destructor(void) {
    destructor_ran = 1;
}

static uintptr_t fixture_ifunc_target(void) {
    return (uintptr_t)(hybris_fixture_dependency_value() + 5);
}

static void* fixture_ifunc_resolver(void) {
    return (void*)&fixture_ifunc_target;
}

int hybris_fixture_constructor_ran(void) { return constructor_ran; }
int hybris_fixture_destructor_ran(void) { return destructor_ran; }
int hybris_fixture_tls_value(const int *value) { return *value; }
int hybris_fixture_dependency_value_from_main(void) {
    return hybris_fixture_dependency_value();
}
uintptr_t hybris_fixture_ifunc(void) __attribute__((ifunc("fixture_ifunc_resolver")));
