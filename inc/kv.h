#ifndef NAKD_KV_H
#define NAKD_KV_H
#include <json-c/json.h>

json_object *nakd_kv(const char *user);
int nakd_kv_set(const char *user, const char *key, json_object *jvalue);
int nakd_kv_set_bulk(const char *user, json_object *jkv);
json_object *nakd_kv_get(const char *user, const char *key);

#endif
