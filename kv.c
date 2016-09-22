#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <json-c/json.h>
#include <pthread.h>
#include "kv.h"
#include "json.h"
#include "nak_mutex.h"
#include "module.h"
#include "log.h"

#define KV_DIR "/etc/nakd/user_data"

static pthread_mutex_t _kv_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *__kv_path(const char *user) {
    static char kv_path[PATH_MAX];
    snprintf(kv_path, sizeof kv_path, KV_DIR "/%s", user);
    return kv_path;
}

static json_object *__kv(const char *user) {
    return nakd_json_parse_file(__kv_path(user));
}

json_object *nakd_kv(const char *user) {
    nakd_mutex_lock(&_kv_mutex);
    json_object *jret = __kv(user);
    nakd_mutex_unlock(&_kv_mutex);
    return jret;
}

int nakd_kv_set(const char *user, const char *key, json_object *jval) {
    nakd_mutex_lock(&_kv_mutex);
    json_object *jukv = __kv(user);
    if (jukv == NULL)
        jukv = json_object_new_object();

    json_object_object_del(jukv, key);
    json_object_object_add(jukv, key, jval);

    int ret = nakd_json_write_file(__kv_path(user), jukv);
    nakd_mutex_unlock(&_kv_mutex);
    return ret;
}

int nakd_kv_set_bulk(const char *user, json_object *jkv) {
    nakd_mutex_lock(&_kv_mutex);
    json_object *jukv = __kv(user);
    if (jukv == NULL)
        jukv = json_object_new_object();

    json_object_object_foreach(jkv, key, jval) {
        json_object_object_del(jukv, key);
        json_object_object_add(jukv, key, jval);
    }
    int ret = nakd_json_write_file(__kv_path(user), jukv);
    nakd_mutex_unlock(&_kv_mutex);
    return ret;
}

json_object *nakd_kv_get(const char *user, const char *key) {
    json_object *jukv = nakd_kv(user);
    if (jukv == NULL)
        return NULL;

    json_object *jobj = NULL;
    json_object_object_get_ex(jukv, key, &jobj);
    if (jobj != NULL) {
        json_object_get(jobj);
        json_object_put(jukv);
    }
    return jobj;
}

static int _kv_init(void) {
    if (access(KV_DIR, X_OK))
        nakd_assert(!mkdir(KV_DIR, 770));
    return 0;
}

static int _kv_cleanup(void) {
    return 0;
}

static struct nakd_module module_kv = {
    .name = "kv",
    .init = _kv_init,
    .cleanup = _kv_cleanup
};
NAKD_DECLARE_MODULE(module_kv);
