#include "drm_lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

static int g_failures;
static int g_running;

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL: %s (%s:%d)\n", #expr, __FILE__, __LINE__); \
        ++g_failures; \
    } \
} while (0)

static void state_cb(const char *state, void *ud)
{
    (void)ud;
    if (state && strcmp(state, "RUNNING") == 0) g_running = 1;
}

int main(void)
{
    SetEnvironmentVariableA("ADAM_DRM_DEBUG", "1");
    _putenv_s("ADAM_DRM_DEBUG", "1");
    SetEnvironmentVariableA("HYBRIS_LINKER_DIR", "C:\\storage\\hybris-linker");
    SetEnvironmentVariableA("HYBRIS_LD_LIBRARY_PATH", "C:\\rootfs\\system\\lib64");

    /* Null/invalid argument guards must not enter the guest libraries. */
    CHECK(drm_lib_init(NULL) == -1);
    CHECK(drm_lib_login(NULL, NULL) == -1);
    CHECK(drm_lib_get_account() == NULL);
    CHECK(drm_lib_get_m3u8(0) == NULL);
    CHECK(drm_lib_get_mv(0, NULL, NULL, NULL) == -1);
    CHECK(drm_lib_open_kd_ctx(NULL, NULL) == NULL);
    CHECK(drm_lib_decrypt(NULL, NULL, 0) == -1);
    CHECK(drm_lib_decrypt_itun(0, NULL, 0, NULL) == -1);

    drm_lib_config_t cfg = {0};
    cfg.base_dir = "C:\\Users\\Podman\\drm_files";
    cfg.lib64_dir = "C:\\rootfs\\system\\lib64";
    cfg.state_cb = state_cb;

    CHECK(drm_lib_init(&cfg) == 0);
    CHECK(g_running == 1);
    CHECK(drm_lib_debug_enabled() == 1);
    CHECK(drm_lib_is_recovery_active() == 0 || drm_lib_is_recovery_active() == 1);

    char *account = drm_lib_get_account();
    CHECK(account != NULL);
    CHECK(account && strstr(account, "storefront_id") != NULL);
    CHECK(account && strstr(account, "music_token") != NULL);
    free(account);

    /* Invalid asset IDs are deterministic API-level failures; no network or
     * guest media code should be entered for them. */
    CHECK(drm_lib_get_m3u8(0) == NULL);
    CHECK(drm_lib_get_mv(0, NULL, NULL, NULL) == -1);
    CHECK(drm_lib_open_kd_ctx("", "") == NULL);
    CHECK(drm_lib_decrypt(NULL, (uint8_t *)"x", 1) == -1);
    CHECK(drm_lib_decrypt_itun(0, (uint8_t *)"x", 1, NULL) == -1);
    CHECK(drm_lib_login(NULL, "password") == -1);
    CHECK(drm_lib_login("user", NULL) == -1);

    drm_lib_shutdown();
    fprintf(stderr, "DRM_API_TEST_%s\n", g_failures ? "FAIL" : "PASS");
    return g_failures ? 1 : 0;
}
