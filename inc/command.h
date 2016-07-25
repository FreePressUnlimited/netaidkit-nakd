#ifndef NAKD_COMMAND_H
#define NAKD_COMMAND_H
#include <json-c/json.h>
#include "module.h"

typedef json_object *(*nakd_cmd_handler)(json_object *jcmd, void *priv);
typedef void (*nakd_response_cb)(json_object *jresp, void *priv);
typedef void (*nakd_timeout_cb)(void *priv);

enum nakd_access_level {
    ACCESS_ROOT,
    ACCESS_USER
};

struct nakd_command {
    const char *name;
    const char *desc;
    const char *usage;
    nakd_cmd_handler handler;
    void *priv;
    enum nakd_access_level access;

    struct nakd_module *module;
};

struct nakd_command *nakd_get_command(const char *name);
void nakd_call_command(const char *name, json_object *jcmd,
           nakd_response_cb cb, nakd_timeout_cb timeout_cb,
                                               void *priv);

json_object *cmd_list(json_object *jcmd, void *arg);

#define NAKD_DECLARE_COMMAND(desc) \
    struct nakd_command * desc ## _ptr \
        __attribute__ ((section (".command"))) = &desc 

#endif
