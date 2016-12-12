#ifndef NAKD_UPDATER_H
#define NAKD_UPDATER_H
#include <json-c/json.h>

json_object *cmd_sysupgrade(json_object *jcmd, void *arg);

#endif
