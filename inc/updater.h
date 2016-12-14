#ifndef NAKD_UPDATER_H
#define NAKD_UPDATER_H
#include <stdio.h>
#include <json-c/json.h>

int nakd_check_update_signature(const char *update_path, FILE** fp_ex);
json_object *cmd_sysupgrade(json_object *jcmd, void *arg);

#endif
