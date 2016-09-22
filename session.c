#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <json-c/json.h>
#include <uuid/uuid.h>
#include <pthread.h>
#include "session.h"
#include "json.h"
#include "log.h"
#include "httpd.h"
#include "module.h"
#include "nak_mutex.h"
#include "misc.h"

#define SESSION_DIR "/tmp/nakd_sessions"

static pthread_mutex_t _session_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char *__session_path(const char *sessid) {
    static char sess_path[PATH_MAX];
    snprintf(sess_path, sizeof sess_path, "%s/%s", SESSION_DIR, sessid);
    return sess_path;
}

static json_object *__session_get_data(const char *sessid) {
    return nakd_json_parse_file(__session_path(sessid));
}

json_object *nakd_session_get_data(const char *sessid) {
    nakd_mutex_lock(&_session_mutex);
    json_object *jret = __session_get_data(sessid);
    nakd_mutex_unlock(&_session_mutex);
    return jret;
}

json_object *nakd_session_get_user(const char *sessid) {
    json_object *jsess = nakd_session_get_data(sessid);
    if (jsess == NULL)
        return NULL;

    json_object *juser = NULL;
    json_object_object_get_ex(jsess, "user", &juser);
    if (juser != NULL) {
        json_object_get(juser);
        nakd_assert(json_object_get_type(juser) == json_type_string);
    }
    return juser;
}

int nakd_session_exists(const char *sessid) {
    nakd_mutex_lock(&_session_mutex);
    int ret = !access(__session_path(sessid), R_OK);
    nakd_mutex_unlock(&_session_mutex);
    return ret;
}

int nakd_session_store_data(const char *sessid,
                      json_object *jsessdata) {
    nakd_mutex_lock(&_session_mutex);
    int ret = nakd_json_write_file(__session_path(sessid), jsessdata);
    nakd_mutex_unlock(&_session_mutex);
    return ret;
}

/* Reserve at least 37 bytes for sessid */
void nakd_gen_sessid(char *sessid) {
    uuid_t uuid;
    /* uses /dev/urandom */
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, sessid);
}

int nakd_session_create(const char *sessid, const char *username,
                                    enum nakd_access_level acl) {
    json_object *jsessdata = json_object_new_object();

    json_object *jacl = json_object_new_string(
         nakd_access_level_string[(int)(acl)]);
    json_object_object_add(jsessdata, "acl", jacl);

    json_object *jusername = json_object_new_string(username);
    json_object_object_add(jsessdata, "user", jusername);

    json_object *jtimestamp = json_object_new_int(monotonic_time());
    json_object_object_add(jsessdata, "timestamp", jtimestamp);

    return nakd_session_store_data(sessid, jsessdata);
}

enum nakd_access_level nakd_session_acl(const char *sessid) {
    enum nakd_access_level acl = ACCESS_ALL;

    json_object *jsessdata = nakd_session_get_data(sessid);
    if (jsessdata == NULL)
        goto ret;

    json_object *jacl = NULL;
    json_object_object_get_ex(jsessdata, "acl", &jacl);
    if (jacl == NULL)
        goto cleanup;

    nakd_assert(json_object_get_type(jacl) == json_type_string);
    acl = nakd_acl_from_string(json_object_get_string(jacl));

cleanup:
    json_object_put(jsessdata);
    /* null-safe */
    json_object_put(jacl);
ret:
    return acl;
}

void nakd_session_destroy(const char *sessid) {
    nakd_mutex_lock(&_session_mutex);
    unlink(__session_path(sessid));
    nakd_mutex_unlock(&_session_mutex);
}

static int _session_init(void) {
    if (access(SESSION_DIR, X_OK))
        nakd_assert(!mkdir(SESSION_DIR, 770));
    return 0;
}

static int _session_cleanup(void) {
    return 0;
}

static struct nakd_module module_session = {
    .name = "session",
    .deps = (const char *[]){ "command", "auth", NULL },
    .init = _session_init,
    .cleanup = _session_cleanup
};
NAKD_DECLARE_MODULE(module_session);
