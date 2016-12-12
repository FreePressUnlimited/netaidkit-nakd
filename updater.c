#include <stdio.h>
#include <unistd.h>
#include <json-c/json.h>
#include "module.h"
#include "command.h"
#include "log.h"
#include "nak_mutex.h"
#include "workqueue.h"
#include "jsonrpc.h"
#include "json.h"
#include "shell.h"
#include "updater.h"

#define UPDATER_PATH "/sbin/sysupgrade"

static void _async_sysupgrade_work(void *priv) {
    json_object *jparams = priv;
    const char *path = json_object_get_string(jparams);

    /*
     * The updater will kill all running processes, let's give the RPC response 
     * a chance to reach the user.
     */
    sleep(1);

    if (access(path, R_OK)) {
        nakd_log(L_CRIT, "Can't access the update image at \"%s\"", path);
        goto refcount;
    } 

    if (nakd_shell_exec("/tmp", NULL, 120, 130, UPDATER_PATH " %s", path))
        nakd_log(L_CRIT, "sysupgrade failed");

refcount:
    json_object_put(jparams);
}

static struct work_desc _async_sysupgrade_desc = {
    .impl = _async_sysupgrade_work,
    .name = "sysupgrade"
};

json_object *cmd_sysupgrade(json_object *jcmd, void *arg) {
    json_object *jresponse = NULL;
    json_object *jparams;

    if ((jparams = nakd_jsonrpc_params(jcmd)) == NULL ||
        json_object_get_type(jparams) != json_type_string) {
        goto params;
    }

    if (nakd_work_pending(nakd_wq, _async_sysupgrade_desc.name)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
                                "Invalid request - already updating");
        goto response;
    }

    const char *path = json_object_get_string(jparams);
    if (access(path, R_OK)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
                     "Can't access the update image at \"%s\"", path);
        goto response;
    } 

    struct work *sysupgrade_wq_entry = nakd_alloc_work(&_async_sysupgrade_desc);
    json_object_get(jparams), sysupgrade_wq_entry->desc.priv = jparams;
    nakd_workqueue_add(nakd_wq, sysupgrade_wq_entry);

    json_object *jresult = json_object_new_string("QUEUED");
    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);
    goto response;

params:
    jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_PARAMS,
       "Invalid parameters - params should be a filesystem path "
                                                       "string");
response:
    return jresponse;
}

static struct nakd_module module_updater = {
    .name = "updater",
    .deps = (const char *[]){ "command", "shell", NULL },
};
NAKD_DECLARE_MODULE(module_updater);

static struct nakd_command sysupgrade = {
    .name = "sysupgrade",
    .desc = "",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"sysupgrade\","
            "\"params\": \"/tmp/sysupgrade-image\", \"id\": 42}",
    .handler = cmd_sysupgrade,
    .access = ACCESS_ADMIN,
    .module = &module_updater
};
NAKD_DECLARE_COMMAND(sysupgrade);
