#ifndef NAKD_SESSION_H
#define NAKD_SESSION_H
#include <json-c/json.h>
#include "command.h"

#define NAK_SESSION_COOKIE "nak_sessid" 

json_object *nakd_session_get_data(const char *sessid);
int nakd_session_store_data(const char *sessid, json_object *jsessdata);
void nakd_gen_sessid(char *sessid);
int nakd_session_create(const char *sessid,
               enum nakd_access_level acl);
enum nakd_access_level nakd_session_acl(const char *sessid);

#endif
