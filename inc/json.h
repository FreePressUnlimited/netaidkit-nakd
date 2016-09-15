#ifndef NAKD_JSON_H
#define NAKD_JSON_H
#include <json-c/json.h>

const char *nakd_json_get_string(json_object *jobject, const char *key);
int nakd_json_get_int(json_object *jobject, const char *key);
int nakd_json_get_bool(json_object *jobject, const char *key);
json_object *nakd_json_parse_file(const char *path);
int nakd_json_write_file(const char *path, json_object *jobj);

#endif
