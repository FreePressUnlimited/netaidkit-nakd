#ifndef NAKD_AUTH_H
#define NAKD_AUTH_H
#include <json-c/json.h>
#include "command.h"

int nakd_user_exists(const char *user);
int nakd_authenticate(const char *user, const char *pass);
int nakd_auth_set(const char *user, const char *pass,
                         enum nakd_access_level acl);
enum nakd_access_level nakd_get_user_acl(const char *user);
int nakd_auth_remove(const char *user);
json_object *nakd_auth_list(void);

#endif
