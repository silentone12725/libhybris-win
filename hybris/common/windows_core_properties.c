#include <hybris/properties/properties.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void property_environment_name(const char *key, char *name, size_t size) {
    size_t i;
    snprintf(name, size, "HYBRIS_PROP_");
    for (i = strlen(name); *key != '\0' && i + 1 < size; ++key) {
        char c = *key;
        name[i++] = c == '.' ? '_' : c;
    }
    name[i] = '\0';
}

int my_property_get(const char *key, char *value, const char *default_value) {
    char name[PROP_NAME_MAX + 16];
    const char *found;
    if (key == NULL || value == NULL) return -1;
    property_environment_name(key, name, sizeof(name));
    found = getenv(name);
    if (found == NULL) found = default_value != NULL ? default_value : "";
    if (strlen(found) >= PROP_VALUE_MAX) return -1;
    strcpy(value, found);
    return 0;
}

int my_property_set(const char *key, const char *value) {
    char name[PROP_NAME_MAX + 16];
    if (key == NULL || value == NULL) return -1;
    property_environment_name(key, name, sizeof(name));
    return _putenv_s(name, value);
}

int my_property_list(void (*callback)(const char *, const char *, void *), void *cookie) {
    (void)callback;
    (void)cookie;
    return 0;
}
