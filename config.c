#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include "nak_uci.h"
#include "log.h"
#include "config.h"
#include "module.h"
#include "nak_mutex.h"

#define CONFIG_UCI_PACKAGE "nakd"
#define CONFIG_UCI_SECTION "nakd"

struct uci_package *_nakd_package = NULL;
static pthread_mutex_t _config_mutex;

struct nakd_config_default {
    const char *key;
    const char *value;
} static _defaults[] = {
    { "LED1_path", "/sys/class/leds/gl-connect:green:lan/brightness" },
    { "LED2_path", "/sys/class/leds/gl-connect:red:wlan/brightness" },
    { "stage", "reset" },
    { "wlan_autoconnect", "1" },
    {}
};

static int _config_init(void) {
    pthread_mutex_init(&_config_mutex, NULL);
    return 0;
}

static int _config_cleanup(void) {
    pthread_mutex_destroy(&_config_mutex);
    return 0;
}

static int _default_config_key(const char *key, char **ret) {
    int status = 1;

    for (struct nakd_config_default *opt = _defaults; opt->key; opt++) {
        if (!strcmp(key, opt->key)) {
            *ret = strdup(opt->value);
            status = 0;
            break;
        }
    }

    if (status) {
        nakd_log(L_CRIT, "No default configuration value for key \"%s\"",
                                                                    key);
    } else {
        nakd_log(L_NOTICE, "Using default value for key \"%s\": \"%s\"",
                                                             key, *ret);
    }
    return status; 
}

int nakd_config_key(const char *key, char **ret) {
    int status = 0;
    nakd_uci_lock();
    nakd_mutex_lock(&_config_mutex);

    struct uci_package *nakd_pkg = nakd_load_uci_package(CONFIG_UCI_PACKAGE);
    if (nakd_pkg == NULL) {
        nakd_log(L_NOTICE, "Couldn't load nakd UCI configuration package \""
                        CONFIG_UCI_PACKAGE "\". Continuing with defaults.");
        status = _default_config_key(key, ret);
        goto unlock;
    }


    struct uci_section *nakd_s = uci_lookup_section(nakd_pkg->ctx, nakd_pkg,
                                                        CONFIG_UCI_SECTION);
    if (nakd_s == NULL) {
        nakd_log(L_NOTICE, "Couldn't find nakd UCI configuration section \""
                        CONFIG_UCI_SECTION "\". Continuing with defaults.");
        status = _default_config_key(key, ret);
        goto cleanup;
    }

    struct uci_option *opt = uci_lookup_option(nakd_s->package->ctx, nakd_s,
                                                                       key);
    if (opt == NULL) {
        nakd_log(L_NOTICE, "Couldn't find nakd UCI configuration option\""
                                  "%s\". Continuing with defaults.", key);
        status = _default_config_key(key, ret);
        goto cleanup;
    }

    if (opt->type != UCI_TYPE_STRING) {
        nakd_log(L_NOTICE, "Option \"%s\" was found, but it isn't a string. "
                                           "Continuing with defaults.", key);
        status = _default_config_key(key, ret);
        goto cleanup;
    }

    *ret = strdup(opt->v.string);

cleanup:
    if (nakd_unload_uci_package(nakd_pkg))
        nakd_log(L_CRIT, "Couldn't unload nakd UCI package.");
unlock:
    pthread_mutex_unlock(&_config_mutex);
    nakd_uci_unlock();
    return status;
}

int nakd_config_key_int(const char *key, int *ret) {
    char *uci_str = NULL;
    if (!nakd_config_key(key, &uci_str)) {
        errno = 0;
        int res = (int)(strtol(uci_str, NULL, 10));
        if (errno) {
            nakd_log(L_CRIT, "Configuration value \"%s\" isn't an integer. "
                       "(key: \"%s\") (%s)", uci_str, key, strerror(errno));
            return 1;
        }
        *ret = res;
        return 0;
    }
    return 1;
}

int nakd_config_set(const char *key, const char *val) {
    int status = 0;
    nakd_uci_lock();
    nakd_mutex_lock(&_config_mutex);

    struct uci_package *nakd_pkg = nakd_load_uci_package(CONFIG_UCI_PACKAGE);
    if (nakd_pkg == NULL) {
        nakd_log(L_NOTICE, "Couldn't load nakd UCI configuration package \""
                   CONFIG_UCI_PACKAGE "\", unable to set config key \"%s\" "
                                                    "to \"%s\".", key, val);
        status = 1;
        goto unlock;
    }

    struct uci_section *nakd_s = uci_lookup_section(nakd_pkg->ctx, nakd_pkg,
                                                        CONFIG_UCI_SECTION);
    if (nakd_s == NULL) {
        nakd_log(L_NOTICE, "Couldn't find nakd UCI configuration section \""
                   CONFIG_UCI_PACKAGE "\", unable to set config key \"%s\" "
                                                    "to \"%s\".", key, val);
        status = 1;
        goto cleanup;
    }

    struct uci_ptr option = {
        .package = nakd_pkg->e.name,
        .section = nakd_s->e.name,
        .option = key,
        .value = val 
    };
    nakd_uci_set(&option);
    /* TODO compare usage w/ existing UCI implementation */
    nakd_uci_save(nakd_pkg);
    nakd_uci_commit(&nakd_pkg, true);
    goto cleanup;

cleanup:
    if (nakd_unload_uci_package(nakd_pkg))
        nakd_log(L_CRIT, "Couldn't unload nakd UCI package.");
unlock:
    pthread_mutex_unlock(&_config_mutex);
    nakd_uci_unlock();
    return status;
}

int nakd_config_set_int(const char *key, int val) {
    char buf[32];
    snprintf(buf, sizeof buf, "%d", val);
    return nakd_config_set(key, buf);
}

static struct nakd_module module_config = {
    .name = "config",
    .deps = (const char *[]){ "uci", NULL },
    .init = _config_init,
    .cleanup = _config_cleanup
};

NAKD_DECLARE_MODULE(module_config);
