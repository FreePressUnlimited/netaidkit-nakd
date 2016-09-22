#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <crypt.h>
#include <json-c/json.h>
#include <pthread.h>
#include "auth.h"
#include "module.h"
#include "json.h"
#include "nak_mutex.h"
#include "command.h"
#include "log.h"
#include "jsonrpc.h"
#include "session.h"

#define AUTH_PATH "/etc/nakd/pass"
#define RAND_SOURCE "/dev/random"

static json_object *_jpass;
static pthread_mutex_t _auth_mutex = PTHREAD_MUTEX_INITIALIZER;

static int _auth_get_random(char *out, size_t n) {
    FILE *fp = fopen(RAND_SOURCE, "r");
    if (fp == NULL)
        return -1;

    int nb_read = fread(out, 1, n, fp);
    fclose(fp);
    return nb_read;
}

static char *__auth_gen_crypt(const char *pass) {
    /* SHA512 isn't available in uClibc by default, using MD5 for now */
    char salt[] = "$1$........";
    const char seedchars[] =
      "./0123456789ABCDEFGHIJKLMNOPQRST"
      "UVWXYZabcdefghijklmnopqrstuvwxyz";
    char randb[sizeof salt - 4];
    nakd_assert(_auth_get_random(randb, sizeof randb) == sizeof randb);

    for (int i = 0; i < sizeof salt - 4; i++)
        salt[3 + i] = seedchars[randb[i] % sizeof seedchars];

    return crypt(pass, salt);
}

static int __auth_verify_crypt(const char *pass, const char *cryptstring) {
    const char *pass_crypt = crypt(pass, cryptstring);
    return strcmp(cryptstring, pass_crypt);
}

static json_object *__auth_find_entry(const char *user) {
    for (int i = 0; i < json_object_array_length(_jpass); i++) {
        json_object *jentry = json_object_array_get_idx(_jpass, i);

        json_object *juser = NULL;
        json_object_object_get_ex(jentry, "user", &juser);
        if (juser == NULL)
            continue;

        nakd_assert(json_object_get_type(juser) == json_type_string);
        const char *entry_user = json_object_get_string(juser);
        if (entry_user == NULL)
            continue;

        if (!strcmp(entry_user, user))
            return jentry;
    }
    return NULL;
}

int nakd_user_exists(const char *user) {
    nakd_mutex_lock(&_auth_mutex);
    int ret = __auth_find_entry(user) != NULL;
    nakd_mutex_unlock(&_auth_mutex);
    return ret;
}

enum nakd_access_level __auth_get_user_acl(const char *user) {
    json_object *jentry = __auth_find_entry(user);
    if (jentry == NULL)
        return ACCESS_ALL;

    json_object *jacl = NULL;
    json_object_object_get_ex(jentry, "acl", &jacl);
    if (jacl == NULL)
        return ACCESS_ALL;

    nakd_assert(json_object_get_type(jacl) == json_type_string);
    const char *aclstr = json_object_get_string(jacl);
    return nakd_acl_from_string(aclstr);
}

enum nakd_access_level nakd_get_user_acl(const char *user) {
    nakd_mutex_lock(&_auth_mutex);
    enum nakd_access_level ret = __auth_get_user_acl(user);
    nakd_mutex_unlock(&_auth_mutex);
    return ret;
}

static int __authenticate(const char *user, const char *pass) {
    json_object *jentry = __auth_find_entry(user);
    if (jentry == NULL)
        return 1;

    json_object *jcrypt = NULL;
    json_object_object_get_ex(jentry, "crypt", &jcrypt);
    if (jcrypt == NULL)
        return 1;

    nakd_assert(json_object_get_type(jcrypt) == json_type_string);
    const char *cryptstring = json_object_get_string(jcrypt);
    if (cryptstring == NULL)
        return 1;

    return __auth_verify_crypt(pass, cryptstring);
}

int nakd_authenticate(const char *user, const char *pass) {
    nakd_mutex_lock(&_auth_mutex);
    int ret = __authenticate(user, pass);
    nakd_mutex_unlock(&_auth_mutex);
    return ret;
}

static void __auth_remove(const char *user) {
    /* TODO json-c: currently there's no way to remove an array element,
     * recheck later or patch in json-c.
     */
    json_object *jupdated = json_object_new_array();

    for (int i = 0; i < json_object_array_length(_jpass); i++) {
        json_object *jentry = json_object_array_get_idx(_jpass, i);

        json_object *juser = NULL;
        json_object_object_get_ex(jentry, "user", &juser);
        if (juser == NULL)
            continue;

        nakd_assert(json_object_get_type(juser) == json_type_string);
        const char *entry_user = json_object_get_string(juser);
        if (!strcmp(user, entry_user))
            continue;

        json_object_get(jentry);
        json_object_array_add(jupdated, jentry);
    }

    json_object_put(_jpass);
    _jpass = jupdated;
}

static void __auth_set(const char *user, const char *pass,
                             enum nakd_access_level acl) {
    __auth_remove(user);

    const char *cryptstring = __auth_gen_crypt(pass);

    json_object *jentry = json_object_new_object();
    json_object *juser = json_object_new_string(user);
    json_object *jcrypt = json_object_new_string(cryptstring);
    json_object *jacl = json_object_new_string(
         nakd_access_level_string[(int)(acl)]);
    json_object_object_add(jentry, "user", juser);
    json_object_object_add(jentry, "crypt", jcrypt);
    json_object_object_add(jentry, "acl", jacl);

    json_object_array_add(_jpass, jentry);
}

static int _auth_write(void) {
    return nakd_json_write_file(AUTH_PATH, _jpass);
}

int nakd_auth_set(const char *user, const char *pass,
                        enum nakd_access_level acl) {
    nakd_mutex_lock(&_auth_mutex);
    __auth_set(user, pass, acl);
    int ret = _auth_write();
    nakd_mutex_unlock(&_auth_mutex);
    return ret;
}

int nakd_auth_remove(const char *user) {
    nakd_mutex_lock(&_auth_mutex);
    __auth_remove(user);
    int ret = _auth_write();
    nakd_mutex_unlock(&_auth_mutex);
    return ret;
}

static json_object *__nakd_auth_list(void) {
    json_object *jresult = json_object_new_array();
    nakd_assert(jresult != NULL);

    for (int i = 0; i < json_object_array_length(_jpass); i++) {
        json_object *jentry = json_object_array_get_idx(_jpass, i);

        /* copy only a part of attributes */
        json_object *juser = NULL;
        json_object_object_get_ex(jentry, "user", &juser);
        json_object *jacl = NULL;
        json_object_object_get_ex(jentry, "acl", &jacl);
        nakd_assert(juser != NULL && jacl != NULL);

        json_object_get(juser);
        json_object_get(jacl);

        json_object *jre = json_object_new_object();
        json_object_object_add(jre, "user", juser);
        json_object_object_add(jre, "acl", jacl);
        json_object_array_add(jresult, jre);
    }
    return jresult;
}

json_object *nakd_auth_list(void) {
    nakd_mutex_lock(&_auth_mutex);
    json_object *jret = __nakd_auth_list();
    nakd_mutex_unlock(&_auth_mutex);
    return jret;
}

static int _auth_init(void) {
    if ((_jpass = nakd_json_parse_file(AUTH_PATH)) == NULL)
        _jpass = json_object_new_array();
    return 0;
}

static int _auth_cleanup(void) {
    json_object_put(_jpass);
    return 0;
}

static struct nakd_module module_auth = {
    .name = "auth",
    .deps = (const char *[]){ "command", NULL },
    .init = _auth_init,
    .cleanup = _auth_cleanup 
};
NAKD_DECLARE_MODULE(module_auth);

json_object *cmd_auth_set(json_object *jcmd, void *arg) {
    json_object *jresponse = NULL;
    json_object *jparams;

    if ((jparams = nakd_jsonrpc_params(jcmd)) == NULL)
        goto params;

    json_object *juser = NULL;
    json_object_object_get_ex(jparams, "user", &juser);
    json_object *jpass = NULL;
    json_object_object_get_ex(jparams, "pass", &jpass);
    json_object *jacl = NULL;
    json_object_object_get_ex(jparams, "acl", &jacl);
    if (juser == NULL || jpass == NULL || jacl == NULL)
        goto params;

    if (json_object_get_type(juser) != json_type_string ||
        json_object_get_type(jpass) != json_type_string ||
        json_object_get_type(jacl) != json_type_string) {
        goto params;
    }

    const char *user = json_object_get_string(juser);
    const char *pass = json_object_get_string(jpass);
    enum nakd_access_level acl = nakd_acl_from_string(
                        json_object_get_string(jacl));

    if (nakd_auth_set(user, pass, acl)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                "Internal error - couldn't write the password file");
    } else {
        json_object *jresult = json_object_new_string("OK");
        jresponse = nakd_jsonrpc_response_success(jcmd, jresult);
    }
    goto response;

params:
    jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
        "Invalid request - params object should contain 'user', 'pass' and "
                                                   "'acl' string objects.");
response:
    return jresponse;
}

static struct nakd_command auth_set = {
    .name = "auth_set",
    .desc = "Sets/Resets user accounts.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"auth_set\","
          "\"params\": {\"user\": \"...\", \"pass\": \"...\", "
       "\"acl\": \"ACCESS_ADMIN or ACCESS_USER\", \"id\": 42}",
    .handler = cmd_auth_set,
    .access = ACCESS_ADMIN,
    .module = &module_auth
};
NAKD_DECLARE_COMMAND(auth_set);

json_object *cmd_auth_remove(json_object *jcmd, void *arg) {
    json_object *jresponse = NULL;
    json_object *jparams;

    if ((jparams = nakd_jsonrpc_params(jcmd)) == NULL)
        goto params;

    if (json_object_get_type(jparams) != json_type_string)
        goto params;

    const char *username = json_object_get_string(jparams);

    if (nakd_auth_remove(username)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                "Internal error - couldn't write the password file");
    } else {
        json_object *jresult = json_object_new_string("OK");
        jresponse = nakd_jsonrpc_response_success(jcmd, jresult);
    }
    goto response;

params:
    jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
          "Invalid request - params object should be a username");
response:
    return jresponse;
}

static struct nakd_command auth_remove = {
    .name = "auth_remove",
    .desc = "Removes user accounts.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"auth_remove\","
                          "\"params\": \"username\", \"id\": 42}",
    .handler = cmd_auth_remove,
    .access = ACCESS_ADMIN,
    .module = &module_auth
};
NAKD_DECLARE_COMMAND(auth_remove);

json_object *cmd_auth_list(json_object *jcmd, void *arg) {
    return nakd_auth_list();
}

static struct nakd_command auth_list = {
    .name = "auth_list",
    .desc = "Lists user accounts.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"auth_list\","
                                                 " \"id\": 42}",
    .handler = cmd_auth_list,
    .access = ACCESS_USER,
    .module = &module_auth
};
NAKD_DECLARE_COMMAND(auth_list);
