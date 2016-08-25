#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <json-c/json.h>
#include "command.h"
#include "shell.h"
#include "log.h"
#include "jsonrpc.h"
#include "module.h"
#include "workqueue.h"
#include "misc.h"

/* see: command.ld, command.h */
extern struct nakd_command *__nakd_command_list[];

struct nakd_command *nakd_get_command(const char *cmd_name) {
    for (struct nakd_command **command = __nakd_command_list; *command;
                                                           command++) {
        if (!strcmp(cmd_name, (*command)->name))
            return *command;
    }
    return NULL;
}

struct call_command_data {
    struct nakd_command *cmd;
    json_object *jcmd;
    nakd_response_cb cb;
    nakd_timeout_cb timeout_cb;
    void *priv;
};

static void _call_command(void *priv) {
    struct call_command_data *d = priv;
    json_object *jresponse;

    if (d->cmd->module != NULL) {
        if (nakd_module_state(d->cmd->module) != NAKD_INITIALIZED) {
            jresponse = nakd_jsonrpc_response_error(d->jcmd, INTERNAL_ERROR,
                          "Internal error - module %s not initialized yet, "
                                 "please try later.", d->cmd->module->name);
            goto response;
        }
    }

    jresponse = d->cmd->handler(d->jcmd, d->cmd->priv);

response:
    if (d->cb != NULL)
        d->cb(jresponse, d->priv);
    free(priv);
}

static void _call_command_timeout(void *priv) {
    struct call_command_data *d = priv;
    if (d->timeout_cb != NULL)
        d->timeout_cb(d->priv);
}

static struct work_desc _call_command_desc = {
    .impl = _call_command,
    .timeout_cb = _call_command_timeout,
    .name = "RPC command",
    .timeout = 20,
    .cancel_on_timeout = 0
};

void nakd_call_command(const char *cmd_name, json_object *jcmd,
               nakd_response_cb cb, nakd_timeout_cb timeout_cb,
                                                  void *priv) {
    struct nakd_command *cmd = nakd_get_command(cmd_name);
    if (cmd == NULL) {
        nakd_log(L_NOTICE, "Couldn't find command %s.", cmd_name);
        json_object *jresponse = nakd_jsonrpc_response_error(jcmd,
           INVALID_REQUEST, "Invalid request - no such command: %s.",
                                                           cmd_name);
        if (cb != NULL)
            cb(jresponse, priv);
        return;
    }

    struct call_command_data *d = malloc(sizeof(struct call_command_data));
    d->cmd = cmd;
    d->jcmd = jcmd;
    d->cb = cb;
    d->timeout_cb = timeout_cb;
    d->priv = priv;

    struct work *command_work = nakd_alloc_work(&_call_command_desc);
    command_work->desc.priv = d;

    nakd_workqueue_add(nakd_wq, command_work);
}

static json_object *_desc_command(struct nakd_command *cmd) {
    json_object *jresult = json_object_new_object();
    
    if (cmd->name != NULL) {
        json_object *jname = json_object_new_string(cmd->name);
        json_object_object_add(jresult, "name", jname);
    }

    if (cmd->desc != NULL) {
        json_object *jdesc = json_object_new_string(cmd->desc);
        json_object_object_add(jresult, "description", jdesc);
    }

    if (cmd->usage != NULL) {
        json_object *jusage = json_object_new_string(cmd->usage);
        json_object_object_add(jresult, "usage", jusage);
    }
    return jresult;
}

json_object *cmd_list(json_object *jcmd, void *arg) {
    json_object *jresult = json_object_new_array();

    for (struct nakd_command **command = __nakd_command_list; *command;
                                                           command++) {
        json_object_array_add(jresult, _desc_command(*command));
    }
    return nakd_jsonrpc_response_success(jcmd, jresult);
}

json_object *nakd_command_timedlock(json_object *jcmd, pthread_mutex_t *lock) {
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += NAKD_COMMAND_MUTEX_TIMEOUT;
    int lock_status = pthread_mutex_timedlock(lock, &timeout);
    if (lock_status == ETIMEDOUT) {
        nakd_log(L_DEBUG, "RPC call lock timed out.");
        return nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                                      "Internal error - busy.");
    } else if (lock_status) {
        nakd_log(L_DEBUG, "RPC call lock error - %s", strerror(lock_status));
        return nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                  "Internal error - %s", strerror(lock_status));
    }
    return NULL;
}

struct nakd_module module_command = {
    .name = "command",
    .deps = (const char *[]){ "workqueue", NULL }
};
NAKD_DECLARE_MODULE(module_command);

static struct nakd_command list = {
    .name = "list",
    .desc = "List available commands.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"list\", \"id\": 42}",
    .handler = cmd_list,
    .access = ACCESS_USER,
    .module = &module_command
};
NAKD_DECLARE_COMMAND(list);
