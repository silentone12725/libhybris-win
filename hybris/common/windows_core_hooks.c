#include "windows_core_compat.h"

#include <hybris/common/hooks.h>
#include <hybris/common/dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *(*android_dlopen_fn)(const char *, int);
typedef void *(*android_dlsym_fn)(void *, const char *);
typedef int (*android_dlclose_fn)(void *);
typedef char *(*android_dlerror_fn)(void);
typedef void (*android_linker_init_fn)(int, void *(*)(const char *, const char *), int);
typedef void *(*android_dlopen_ext_fn)(const char *, int, const void *);
typedef void (*android_get_path_fn)(char *, size_t);
typedef void (*android_update_path_fn)(const char *);

static HMODULE linker_module;
static android_dlopen_fn linker_dlopen;
static android_dlsym_fn linker_dlsym;
static android_dlclose_fn linker_dlclose;
static android_dlerror_fn linker_dlerror;
static android_dlopen_ext_fn linker_dlopen_ext;
static android_get_path_fn linker_get_path;
static android_update_path_fn linker_update_path;
static char windows_dlerror[256];
static hybris_hook_cb hook_callback;

static void windows_set_error(const char *message) {
    snprintf(windows_dlerror, sizeof(windows_dlerror), "%s", message);
}

static void *windows_symbol(const char *name) {
    FARPROC raw;
    void *result = NULL;
    if (linker_module == NULL) return NULL;
    raw = GetProcAddress(linker_module, name);
    memcpy(&result, &raw, sizeof(result));
    return result;
}

static int windows_linker_init(void) {
    char path[MAX_PATH];
    const char *directory;
    android_linker_init_fn init;

    if (linker_module != NULL) return linker_dlopen != NULL ? 0 : -1;

    directory = getenv("HYBRIS_LINKER_DIR");
    if (directory == NULL || directory[0] == '\0') directory = ".";
    snprintf(path, sizeof(path), "%s/q.so", directory);
    linker_module = LoadLibraryA(path);
    if (linker_module == NULL) {
        snprintf(windows_dlerror, sizeof(windows_dlerror),
                 "LoadLibraryA(%s) failed (%lu)", path,
                 (unsigned long)GetLastError());
        return -1;
    }

    linker_dlopen = (android_dlopen_fn)windows_symbol("android_dlopen");
    linker_dlsym = (android_dlsym_fn)windows_symbol("android_dlsym");
    linker_dlclose = (android_dlclose_fn)windows_symbol("android_dlclose");
    linker_dlerror = (android_dlerror_fn)windows_symbol("android_dlerror");
    linker_dlopen_ext = (android_dlopen_ext_fn)windows_symbol("android_dlopen_ext");
    linker_get_path = (android_get_path_fn)windows_symbol("android_get_LD_LIBRARY_PATH");
    linker_update_path = (android_update_path_fn)windows_symbol("android_update_LD_LIBRARY_PATH");
    init = (android_linker_init_fn)windows_symbol("android_linker_init");
    if (linker_dlopen == NULL || linker_dlsym == NULL || linker_dlclose == NULL ||
        linker_dlerror == NULL || init == NULL) {
        windows_set_error("Q linker exports are incomplete");
        return -1;
    }

    init(29, hook_callback, 0);
    return 0;
}

void hybris_set_hook_callback(hybris_hook_cb callback) {
    hook_callback = callback;
}

void *android_dlopen(const char *filename, int flag) {
    if (windows_linker_init() != 0) return NULL;
    return linker_dlopen(filename, flag);
}

char *android_dlerror(void) {
    if (linker_dlerror != NULL) return linker_dlerror();
    return windows_dlerror[0] != '\0' ? windows_dlerror : NULL;
}

void *android_dlsym(void *handle, const char *symbol) {
    if (windows_linker_init() != 0) return NULL;
    return linker_dlsym(handle, symbol);
}

int android_dlclose(void *handle) {
    if (windows_linker_init() != 0) return -1;
    return linker_dlclose(handle);
}

void *android_dlopen_ext(const char *filename, int flag, const void *extinfo) {
    if (windows_linker_init() != 0 || linker_dlopen_ext == NULL) return NULL;
    return linker_dlopen_ext(filename, flag, extinfo);
}

void android_get_LD_LIBRARY_PATH(char *buffer, size_t buffer_size) {
    if (windows_linker_init() == 0 && linker_get_path != NULL)
        linker_get_path(buffer, buffer_size);
}

void android_update_LD_LIBRARY_PATH(const char *path) {
    if (windows_linker_init() == 0 && linker_update_path != NULL)
        linker_update_path(path);
}

void *hybris_dlopen(const char *filename, int flag) { return android_dlopen(filename, flag); }
void *hybris_dlsym(void *handle, const char *symbol) { return android_dlsym(handle, symbol); }
int hybris_dlclose(void *handle) { return android_dlclose(handle); }
char *hybris_dlerror(void) { return android_dlerror(); }
int hybris_dladdr(const void *addr, void *info) {
    (void)addr;
    (void)info;
    errno = ENOSYS;
    return 0;
}
