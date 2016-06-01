#include <json-c/json.h>
#include <string.h>
#include <errno.h>
#include "json.h"
#include "log.h"

/* json-c isn't thread-safe, and AFAIK it's the only way of making a deep
 * copy. Let's come back to it later.
 */
json_object *nakd_json_deepcopy(json_object *object) {
    const char *object_str = json_object_get_string(object);
    json_tokener *jtok = json_tokener_new();
    json_object *jresult = json_tokener_parse_ex(jtok, object_str,
                                              strlen(object_str));
    nakd_assert(json_tokener_get_error(jtok) == json_tokener_success);
    nakd_assert(jresult != NULL);
    json_tokener_free(jtok);
    return jresult;
}

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
