#include <json-c/json.h>
#include <string.h>
#include <errno.h>
#include "json.h"
#include "log.h"

const char *nakd_json_get_string(json_object *jobject, const char *key) {
    json_object *jstr = NULL;
    json_object_object_get_ex(jobject, key, &jstr);
    if (jstr == NULL || json_object_get_type(jstr) != json_type_string)
        return NULL;

    return json_object_get_string(jstr);
}

int nakd_json_get_int(json_object *jobject, const char *key) {
    json_object *jint = NULL;
    json_object_object_get_ex(jobject, key, &jint);
    if (jint != NULL) {
        if (json_object_get_type(jint) != json_type_int)
            goto err;
        return json_object_get_int(jint);
    }
err:
    errno = EINVAL;
    return -1;   
}

int nakd_json_get_bool(json_object *jobject, const char *key) {
    json_object *jbool = NULL;
    json_object_object_get_ex(jobject, key, &jbool);
    if (jbool != NULL) {
        if (json_object_get_type(jbool) != json_type_boolean)
            goto err;
        return json_object_get_boolean(jbool);
    }
err:
    return -1;
}

json_object *nakd_json_parse_file(const char *path) {
    char buf[1024];
    json_object *jresult = NULL;

    json_tokener *jtok = json_tokener_new();
    nakd_assert(jtok != NULL);

    FILE *fp = fopen(path, "r");
    if (fp == NULL)
        goto ret;

    size_t nb_read;
    enum json_tokener_error jerr;
    do {
        nb_read = fread(buf, 1, sizeof buf, fp);
        jresult = json_tokener_parse_ex(jtok, buf, nb_read); 
        jerr = json_tokener_get_error(jtok);
    } while (nb_read && jerr == json_tokener_continue);

cleanup:
    json_tokener_free(jtok);
    fclose(fp);
ret:
    /* jresult == NULL in case of parse error */
    return jresult;
}

int nakd_json_write_file(const char *path, json_object *jobj) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return 1;

    const char *jstr = json_object_to_json_string_ext(jobj,
                                  JSON_C_TO_STRING_PRETTY);
    fwrite(jstr, strlen(jstr), 1, fp);
    fclose(fp);
    return 0;
}
