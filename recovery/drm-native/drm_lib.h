/* In-process DRM API used by the Windows wrapper and its test harness. */
#pragma once

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*drm_auth_cb_t)(const char *, char *, int, void *);
typedef void (*drm_state_cb_t)(const char *, void *);

typedef struct {
    const char *base_dir;
    const char *lib64_dir;
    const char *username;
    const char *password;
    const char *device_info;
    int offline_only;
    drm_auth_cb_t auth_cb;
    void *auth_ud;
    drm_state_cb_t state_cb;
    void *state_ud;
} drm_lib_config_t;

int drm_lib_init(const drm_lib_config_t *cfg);
void drm_lib_shutdown(void);
int drm_lib_login(const char *username, const char *password);
char *drm_lib_get_m3u8(unsigned long adam_id);
char *drm_lib_get_account(void);
int drm_lib_get_mv(unsigned long adam_id, char **out_url, char **out_dk,
                   int *out_has_itun);
void *drm_lib_open_kd_ctx(const char *adam_id, const char *uri);
int drm_lib_decrypt(void *kd_ctx, uint8_t *sample, uint32_t size);
int drm_lib_decrypt_itun(unsigned long adam_id, uint8_t *sample,
                         uint32_t in_size, uint32_t *out_size);
int drm_lib_is_recovery_active(void);
int drm_lib_debug_enabled(void);
#define DRM_DEBUG(...) \
    do { if (drm_lib_debug_enabled()) fprintf(stderr, __VA_ARGS__); } while (0)

#ifdef __cplusplus
}
#endif
