#include <stdint.h>

__thread int hybris_tls_model_value = 7;

int hybris_tls_model_read(void) {
    return hybris_tls_model_value;
}

void hybris_tls_model_write(int value) {
    hybris_tls_model_value = value;
}

uintptr_t hybris_tls_model_address(void) {
    return (uintptr_t)&hybris_tls_model_value;
}
