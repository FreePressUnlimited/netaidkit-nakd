#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <json-c/json.h>
#include <uuid/uuid.h>
#include "session.h"
#include "json.h"
#include "log.h"
#include "httpd.h"
#include "module.h"

#define SESSION_DIR "/tmp/nakd_sessions"

json_object *nakd_session_get_data(const char *sessid) {
    char sess_path[PATH_MAX];
    snprintf(sess_path, sizeof sess_path, "%s/%s", SESSION_DIR, sessid);
    return nakd_json_parse_file(sess_path);
}

int nakd_session_store_data(const char *sessid,
                      json_object *jsessdata) {
    char sess_path[PATH_MAX];
    snprintf(sess_path, sizeof sess_path, "%s/%s", SESSION_DIR, sessid);

    nakd_assert(jsessdata != NULL);
    const char *jdatastr = json_object_to_json_string_ext(jsessdata,
                                           JSON_C_TO_STRING_PRETTY);

    FILE *fp = fopen(sess_path, "w");
    if (fp == NULL)
        return 0;
    fputs(jdatastr, fp);
    fclose(fp);
    return 1;
}

/* Reserve at least 37 bytes for sessid */
void nakd_gen_sessid(char *sessid) {
    uuid_t uuid;
    /* uses /dev/urandom */
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, sessid);
}

int nakd_session_create(const char *sessid,
              enum nakd_access_level acl) {
    json_object *jsessdata = json_object_new_object();
    json_object *jacl = json_object_new_string(
         nakd_access_level_string[(int)(acl)]);
    json_object_object_add(jsessdata, "acl", jacl);
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
