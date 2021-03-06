#include <unistd.h>
#include <string.h>
#include <linux/limits.h>
#include <pthread.h>
#include <json-c/json.h>
#include "stage.h"
#include "hooks.h"
#include "log.h"
#include "command.h"
#include "jsonrpc.h"
#include "shell.h"
#include "openvpn.h"
#include "nak_uci.h"
#include "module.h"
#include "connectivity.h"
#include "timer.h"
#include "workqueue.h"
#include "config.h"
#include "nak_mutex.h"
#include "wlan.h"

#define NAKD_STAGE_SCRIPT_PATH NAKD_SCRIPT_PATH "stage/"
#define NAKD_STAGE_SCRIPT_DIR_FMT (NAKD_STAGE_SCRIPT_PATH "%s")

#define STAGE_UPDATE_INTERVAL 2500 /* ms */

static pthread_mutex_t _stage_change_mutex;
static struct nakd_timer *_stage_update_timer;

static void toggle_rule(const char *hook_name, const char *state,
                                      struct uci_option *option);
static struct nakd_uci_hook _firewall_hooks[] = {
    /* rewrite firewall rules */
    {"nak_rule_enable", toggle_rule},
    {"nak_rule_disable", toggle_rule},
    {NULL, NULL}
};

struct {
    const char *error;
    const char *step_name;
    int step_count;
    int step;
} static _stage_status;
static pthread_mutex_t _stage_status_mutex;

static void __clear_stage_status(void) {
    memset(&_stage_status, 0, sizeof _stage_status);
}

static void _clear_stage_status(void) {
    nakd_mutex_lock(&_stage_status_mutex);
    __clear_stage_status();
    pthread_mutex_unlock(&_stage_status_mutex);
}

static int _run_stage_scripts(const struct stage *stage);
static int _start_openvpn(const struct stage *stage);
static int _stop_openvpn(const struct stage *stage);
static int _run_uci_hooks(const struct stage *stage);
static int _reset_wlan(const struct stage *stage);
static int _reset_default_stage(const struct stage *stage);

static struct stage _stage_reset = {
    .name = "reset",
    .desc = "",
    .work_start = (struct stage_step[]){
       { 
            .name = "Resetting WLAN",
            .desc = "",
            .work = _reset_wlan
       },
       { 
            .name = "Resetting stage configuration",
            .desc = "",
            .work = _reset_default_stage
       },
       { 
            .name = "Calling UCI hooks",
            .desc = "",
            .work = _run_uci_hooks 
       },
       { 
            .name = "Running stage shell script",
            .desc = "",
            .work = _run_stage_scripts 
       },
       {}
    },
    .hooks = _firewall_hooks,
    .connectivity_level = CONNECTIVITY_NONE,
    .update_default_stage = 0,
    .led = {
        .name = "stage_reset",
        .priority = LED_PRIORITY_MODE,
        .states = (struct led_state[]){
            { "LED1_path", NULL, 1 },
            { "LED2_path", NULL, 1 },
            {}
        },
        .blink.on = 0,
    },
    /* set this stage even if _current_stage == "reset" */
    .force_set = 1
};

static struct stage _stage_setup = {
    .name = "setup",
    .desc = "",
    .work_start = (struct stage_step[]){
       { 
            .name = "Calling UCI hooks",
            .desc = "",
            .work = _run_uci_hooks 
       },
       { 
            .name = "Running stage shell script",
            .desc = "",
            .work = _run_stage_scripts 
       },
       {}
    },
    .hooks = _firewall_hooks,
    .connectivity_level = CONNECTIVITY_NONE,
    .update_default_stage = 1,
    .led = {
        .name = "stage_offline",
        .priority = LED_PRIORITY_MODE,
        .states = (struct led_state[]){
            { "LED1_path", NULL, 1 },
            { "LED2_path", NULL, 1 },
            {}
        },
        .blink.on = 0,
    },
};

static struct stage _stage_offline = {
    .name = "offline",
    .desc = "",
    .work_start = (struct stage_step[]){
       { 
            .name = "Calling UCI hooks",
            .desc = "",
            .work = _run_uci_hooks 
       },
       { 
            .name = "Running stage shell script",
            .desc = "",
            .work = _run_stage_scripts 
       },
       {}
    },
    .hooks = _firewall_hooks,
    .connectivity_level = CONNECTIVITY_NONE,
    .update_default_stage = 1,
    .led = {
        .name = "stage_offline",
        .priority = LED_PRIORITY_MODE,
        .states = (struct led_state[]){
            { "LED1_path", NULL, 1 },
            { "LED2_path", NULL, 1 },
            {}
        },
        .blink.on = 0,
    },
};

static struct stage _stage_vpn = {
    .name = "vpn",
    .desc = "",
    .work_start = (struct stage_step[]){
       { 
            .name = "Calling UCI hooks",
            .desc = "",
            .work = _run_uci_hooks 
       },
       { 
            .name = "Running stage shell script",
            .desc = "",
            .work = _run_stage_scripts 
       },
       { 
            .name = "Starting OpenVPN",
            .desc = "",
            .work = _start_openvpn
       },
       {}
    },
    .work_stop = (struct stage_step[]){
       { 
            .name = "Stopping OpenVPN",
            .desc = "",
            .work = _stop_openvpn
       },
       {}
    },
    .hooks = _firewall_hooks,
    .connectivity_level = CONNECTIVITY_LOCAL,
    .update_default_stage = 1,
    .led = {
        .name = "stage_vpn",
        .priority = LED_PRIORITY_MODE,
        .states = (struct led_state[]){
            { "LED1_path", NULL, 1 },
            { "LED2_path", NULL, 0 },
            {}
        },
        .blink.on = 0,
    },
};

static struct stage _stage_tor = {
    .name = "tor",
    .desc = "",
    .work_start = (struct stage_step[]){
       { 
            .name = "Calling UCI hooks",
            .desc = "",
            .work = _run_uci_hooks 
       },
       { 
            .name = "Running stage shell script",
            .desc = "",
            .work = _run_stage_scripts 
       },
       {}
    },
    .hooks = _firewall_hooks,
    .connectivity_level = CONNECTIVITY_LOCAL,
    .update_default_stage = 1,
    .led = {
        .name = "stage_tor",
        .priority = LED_PRIORITY_MODE,
        .states = (struct led_state[]){
            { "LED1_path", NULL, 1 },
            { "LED2_path", NULL, 0 },
            {}
        },
        .blink.on = 0,
    },
};

static struct stage _stage_online = {
    .name = "online",
    .desc = "",
    .work_start = (struct stage_step[]){
       { 
            .name = "Calling UCI hooks",
            .desc = "",
            .work = _run_uci_hooks 
       },
       { 
            .name = "Running stage shell script",
            .desc = "",
            .work = _run_stage_scripts 
       },
       {}
    },
    .hooks = _firewall_hooks,
    .connectivity_level = CONNECTIVITY_LOCAL,
    .update_default_stage = 1,
    .led = {
        .name = "stage_online",
        .priority = LED_PRIORITY_MODE,
        .states = (struct led_state[]){
            { "LED1_path", NULL, 0 },
            { "LED2_path", NULL, 1 },
            {}
        },
        .blink.on = 0,
    },
};

static struct stage *_stages[] = {
    &_stage_reset,
    &_stage_setup,
    &_stage_offline,
    &_stage_vpn,
    &_stage_tor,
    &_stage_online,
    NULL
};

static struct led_condition _led_stage_working = {
    .name = "stage-working",
    .priority = LED_PRIORITY_NOTIFICATION,
    .states = (struct led_state[]){
        { "LED1_path", NULL, 1 },
        { "LED2_path", NULL, 1 },
        {}
    },
    .blink.on = 1,
    .blink.interval = 100,
    .blink.count = -1, /*infinite */
};

static struct stage *_current_stage = NULL;
static struct stage *_requested_stage = NULL;

static int _step_count(const struct stage_step *work) {
    int n = 0;
    for (; work->name; work++)
        n++;
    return n;
}

static void toggle_rule(const char *hook_name, const char *state,
                                    struct uci_option *option) {
    nakd_assert(hook_name != NULL && state != NULL && option != NULL);

    struct uci_context *ctx = option->section->package->ctx;
    nakd_assert(ctx != NULL);

    struct uci_section *section = option->section;
    nakd_assert(section != NULL);

    const char *name = uci_lookup_option_string(ctx, section, "name");
    if (name == NULL)
        name = "";

    int rule_disable = strcasecmp(hook_name, "nak_rule_enable");

    nakd_log(L_NOTICE, "%s rule \"%s\"", rule_disable ? "Disabling" :
                                                   "Enabling", name);

    const char *value = rule_disable ? "0" : "1";
    struct uci_ptr new_opt_enabled_ptr = {
        .package = option->section->package->e.name,
        .section = option->section->e.name,
        .option = "enabled",
        .value = value 
    };
    nakd_assert(!uci_set(ctx, &new_opt_enabled_ptr));
}

static int _run_stage_scripts(const struct stage *stage) {
    char dirpath[PATH_MAX];
    snprintf(dirpath, sizeof dirpath, NAKD_STAGE_SCRIPT_DIR_FMT, stage->name);
    nakd_uci_lock();
    nakd_shell_run_scripts(dirpath, 0, 0);
    nakd_uci_unlock();
}

static int _start_openvpn(const struct stage *stage) {
    if (nakd_start_openvpn()) {
        nakd_mutex_lock(&_stage_status_mutex);
        _stage_status.error = "Internal error while starting OpenVPN daemon";
        pthread_mutex_unlock(&_stage_status_mutex);
        return 1;
    }
    return 0;
}

static int _stop_openvpn(const struct stage *stage) {
    if (nakd_stop_openvpn()) {
        nakd_mutex_lock(&_stage_status_mutex);
        _stage_status.error = "Internal error while stopping OpenVPN daemon";
        pthread_mutex_unlock(&_stage_status_mutex);
        return 1;
    }
    return 0;
}

static int _run_uci_hooks(const struct stage *stage) {
    if (nakd_call_uci_hooks(stage->hooks, stage->name,
              (const char *[]){ "firewall", NULL })) {
        nakd_mutex_lock(&_stage_status_mutex);
        _stage_status.error = "Internal error while rewriting UCI configuration";
        pthread_mutex_unlock(&_stage_status_mutex);
        return 1;
    }
    return 0;
}

static int _reset_wlan(const struct stage *stage) {
    nakd_wlan_reset_stored();
    nakd_wlan_disconnect();
    return 0;
}

static int _reset_default_stage(const struct stage *stage) {
    return nakd_config_set("stage", _stage_setup.name);
}

static int _run_stage_steps(const struct stage *stage,
                      const struct stage_step *steps) {
    if (steps == NULL)
        return 0;

    _clear_stage_status();
    nakd_mutex_lock(&_stage_status_mutex);
    _stage_status.step_count = _step_count(steps);
    pthread_mutex_unlock(&_stage_status_mutex);

    for (; steps->name != NULL; steps++) {
        nakd_mutex_lock(&_stage_status_mutex);
        _stage_status.step++;
        _stage_status.step_name = steps->name;
        pthread_mutex_unlock(&_stage_status_mutex);

        nakd_log(L_INFO, "Stage %s step: %s (%d/%d)", stage->name,
                                  steps->name, _stage_status.step,
                                        _stage_status.step_count);
        if (steps->work(stage))
            return 1;
    }
    return 0;
}

static int _connectivity_check(const struct stage *stage,
                         enum nakd_connectivity *current,
                        enum nakd_connectivity *needed) {
    enum nakd_connectivity current_connectivity = nakd_connectivity();
    enum nakd_connectivity needed_connectivity = stage->connectivity_level;

    if (current != NULL)
        *current = current_connectivity;
    if (needed != NULL)
        *needed = needed_connectivity;

    /* returns 0 if passed */
    return (int)(current_connectivity) < (int)(needed_connectivity);
}

static void _stage_spec(void *priv) {
    nakd_mutex_lock(&_stage_change_mutex);
    nakd_led_condition_add(&_led_stage_working);

    nakd_mutex_lock(&_stage_status_mutex);
    if (_requested_stage == NULL || (_current_stage == _requested_stage
                                    && !_requested_stage->force_set)) {
        _requested_stage = NULL;
        pthread_mutex_unlock(&_stage_status_mutex);
        goto unlock;
    }
    pthread_mutex_unlock(&_stage_status_mutex);

    _clear_stage_status();

    enum nakd_connectivity current_connectivity;
    enum nakd_connectivity needed_connectivity;
    if (_connectivity_check(_requested_stage, &current_connectivity, &needed_connectivity)) {
        nakd_log(L_INFO, "Insufficient connectivity level for stage %s. "
                       "(current: %s, required: %s) - change postponed.",
                                                  _requested_stage->name,
                   nakd_connectivity_string[(int)(current_connectivity)],
                   nakd_connectivity_string[(int)(needed_connectivity)]);

        nakd_mutex_lock(&_stage_status_mutex);
        _stage_status.error = "Insufficient connectivity level.";
        pthread_mutex_unlock(&_stage_status_mutex);
        goto unlock;
    }

    if (_current_stage != NULL) {
        nakd_log(L_INFO, "Cleaning up after %s stage.", _current_stage->name);
        if(_run_stage_steps(_current_stage, _current_stage->work_stop))
            goto unlock;
    }

    nakd_log(L_INFO, "Stage %s", _requested_stage->name);
    struct stage *previous = _current_stage;

    /*
     * stage_step implementation will return 1 with updated
     * _stage_status->error in case of failure.
     */
    if (_run_stage_steps(_requested_stage, _requested_stage->work_start))
        goto unlock;

    nakd_mutex_lock(&_stage_status_mutex);
    _current_stage = _requested_stage;
    _requested_stage = NULL;
    pthread_mutex_unlock(&_stage_status_mutex);
    nakd_log(L_INFO, "Stage %s: done!", _current_stage->name);

    _clear_stage_status();

    if (previous != NULL)
        nakd_led_condition_remove(previous->led.name);
    nakd_led_condition_add(&_current_stage->led);

unlock:
    nakd_led_condition_remove(_led_stage_working.name);
    pthread_mutex_unlock(&_stage_change_mutex);
}

static struct work_desc _stage_work_desc = {
    .impl = _stage_spec,
    .name = "stage",
    .priv = &_requested_stage
};

static void _stage_update_cb(siginfo_t *timer_info,
                        struct nakd_timer *timer) {
    nakd_log_timer(timer);

    if (!nakd_work_pending(nakd_wq, _stage_work_desc.name)) {
        struct work *stage_wq_entry = nakd_alloc_work(&_stage_work_desc);
        nakd_workqueue_add(nakd_wq, stage_wq_entry);
    }
}

static struct stage *_get_stage(const char *name) {
    for (struct stage **stage = _stages; *stage != NULL; stage++) {
        if (!strcmp((*stage)->name, name))
            return *stage;
    }
    return NULL;
}

static int _stage_init(void) {
    pthread_mutex_init(&_stage_change_mutex, NULL);
    pthread_mutex_init(&_stage_status_mutex, NULL);

    nakd_stage_spec_synch(&_stage_offline, 0);

    char *config_stage_name = NULL;
    if (!nakd_config_key("stage", &config_stage_name)) {
        struct stage *config_stage = _get_stage(config_stage_name);
        if (config_stage != NULL) {
            nakd_stage_spec_synch(config_stage, 0);
        } else {
            nakd_log(L_WARNING, "Misconfigured stage: %s, skipping.",
                                                  config_stage_name);
        }
    }

    /* retry automatically */
    _stage_update_timer = nakd_timer_add(STAGE_UPDATE_INTERVAL,
                              _stage_update_cb, NULL, "stage");
    return 0;
}

static int _stage_cleanup(void) {
    timer_delete(_stage_update_timer);
    pthread_mutex_destroy(&_stage_change_mutex);
    pthread_mutex_destroy(&_stage_status_mutex);
    return 0;
}

static int _stage_spec_update_requested(struct stage *stage, int save) {
    nakd_mutex_lock(&_stage_change_mutex);
    nakd_mutex_lock(&_stage_status_mutex);
    _requested_stage = stage;
    if (save == 1 || save == -1 && stage->update_default_stage)
        nakd_config_set("stage", stage->name);
    pthread_mutex_unlock(&_stage_status_mutex);
    pthread_mutex_unlock(&_stage_change_mutex);
}

void nakd_stage_spec(struct stage *stage, int save) {
    _clear_stage_status();
    _stage_spec_update_requested(stage, save);

    struct work *stage_wq_entry = nakd_alloc_work(&_stage_work_desc);
    nakd_workqueue_add(nakd_wq, stage_wq_entry);
}

void nakd_stage_spec_synch(struct stage *stage, int save) {
    _clear_stage_status();
    _stage_spec_update_requested(stage, save);

    _stage_spec(NULL);
}

int nakd_stage(const char *stage_name) {
    struct stage *stage = _get_stage(stage_name);
    if (stage == NULL) {
        nakd_log(L_CRIT, "No such stage: \"%s\".", stage_name);
        return 1;
    }

    nakd_stage_spec(stage, -1);
    return 0;
}

json_object *cmd_stage_set(json_object *jcmd, void *param) {
    json_object *jresponse;

    if ((jresponse = nakd_command_timedlock(jcmd, &_stage_status_mutex))
                                                              != NULL) {
        goto response;
    }

    /*
     *  If there already is a stage change queued and the connectivity
     *  level is sufficient...
     */
    int busy = _requested_stage != NULL && !_connectivity_check(
                                  _requested_stage, NULL, NULL);
    const char *requested_name;
    if (busy)
        requested_name = _requested_stage->name;
    pthread_mutex_unlock(&_stage_status_mutex);
    if (busy) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
                   "Invalid request - already switching to %s stage.",
                                                      requested_name);
        goto response;
    }

    json_object *jparams = nakd_jsonrpc_params(jcmd);
    if (jparams == NULL || json_object_get_type(jparams) != json_type_string) {
        nakd_log(L_NOTICE, "Couldn't get stage parameter");
        jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_PARAMS,
            "Invalid parameters - params should be a string");
        goto response;
    }

    const char *stage = json_object_get_string(jparams);
    if (!nakd_stage(stage)) {
        json_object *jresult = json_object_new_string("QUEUED");
        jresponse = nakd_jsonrpc_response_success(jcmd, jresult);
    } else {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                                                    "No such stage");
    }

response:
    return jresponse;
}

static json_object *__desc_stage_step(struct stage_step *step) {
    json_object *jresult = json_object_new_object();
    json_object *jname = json_object_new_string(step->name);
    json_object *jdesc = json_object_new_string(step->desc);
    json_object_object_add(jresult, "name", jname);
    json_object_object_add(jresult, "desc", jdesc);
    return jresult;
}

static json_object *__desc_stage(struct stage *stage) {
    json_object *jresult = json_object_new_object();
    json_object *jname = json_object_new_string(stage->name);
    json_object *jdesc = json_object_new_string(stage->desc);
    json_object *jconnectivity = json_object_new_string(
        nakd_connectivity_string[stage->connectivity_level]);

    json_object_object_add(jresult, "name", jname);
    json_object_object_add(jresult, "desc", jdesc);
    json_object_object_add(jresult, "required_connectivity", jconnectivity);
    return jresult;
}

const struct stage *nakd_stage_current(void) {
    nakd_mutex_lock(&_stage_status_mutex);
    const struct stage * current = (const struct stage *)(_current_stage);
    pthread_mutex_unlock(&_stage_status_mutex);
    return current;
}

const struct stage *nakd_stage_requested(void) {
    nakd_mutex_lock(&_stage_status_mutex);
    const struct stage *requested = (const struct stage *)(_requested_stage);
    pthread_mutex_unlock(&_stage_status_mutex);
    return requested ;
}

json_object *cmd_stage_current(json_object *jcmd, void *param) {
    json_object *jresponse;

    if ((jresponse = nakd_command_timedlock(jcmd, &_stage_status_mutex))
                                                              != NULL) {
        goto response;
    }

    json_object *jresult;
    if (_current_stage != NULL)
        jresult = __desc_stage(_current_stage);
    else
        jresult = json_object_new_string("No stage set.");

    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);
    pthread_mutex_unlock(&_stage_status_mutex);

response:
    return jresponse;
}

json_object *cmd_stage_requested(json_object *jcmd, void *param) {
    json_object *jresponse;

    if ((jresponse = nakd_command_timedlock(jcmd, &_stage_status_mutex))
                                                              != NULL) {
        goto response;
    }

    json_object *jresult;
    if (_requested_stage != NULL)
        jresult = __desc_stage(_requested_stage);
    else
        jresult = json_object_new_string("No requested stage.");

    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);
    pthread_mutex_unlock(&_stage_status_mutex);

response:
    return jresponse;
}

json_object *cmd_stage_status(json_object *jcmd, void *param) {
    json_object *jresponse;

    if ((jresponse = nakd_command_timedlock(jcmd, &_stage_status_mutex))
                                                              != NULL) {
        goto response;
    }

    json_object *jresult = json_object_new_object();
    if (_stage_status.error != NULL) {
        json_object *jerror = json_object_new_string(_stage_status.error);
        json_object_object_add(jresult, "error", jerror);
    }
    if (_stage_status.step_name != NULL) {
        json_object *jstep_name =
            json_object_new_string(_stage_status.step_name);
        json_object_object_add(jresult, "step_name", jstep_name);

        json_object *jstep_count =
            json_object_new_int(_stage_status.step_count);
        json_object_object_add(jresult, "step_count", jstep_count);
        json_object *jstep = json_object_new_int(_stage_status.step);
        json_object_object_add(jresult, "step", jstep);
    }

    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);
    pthread_mutex_unlock(&_stage_status_mutex);

response:
    return jresponse;
}

json_object *cmd_stage_list(json_object *jcmd, void *param) {
    json_object *jresult = json_object_new_array();
    for (struct stage **stage = _stages; *stage != NULL; stage++) {
        json_object *jdesc = __desc_stage(*stage);
        json_object_array_add(jresult, jdesc);
    }
    json_object *jresponse = nakd_jsonrpc_response_success(jcmd, jresult);
    return jresponse;
}

static struct nakd_module module_stage = {
    .name = "stage",
    .deps = (const char *[]){ "workqueue", "connectivity", "notification",
               "timer", "config", "uci", "led", "command", "wlan", NULL },
    .init = _stage_init,
    .cleanup = _stage_cleanup
};
NAKD_DECLARE_MODULE(module_stage);

static struct nakd_command stage_set = {
    .name = "stage_set",
    .desc = "Requests asynchronous change of NAK stage.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"stage_set\", \"params\":"
                                                     "\"vpn\", \"id\": 42}",
    .handler = cmd_stage_set,
    .access = ACCESS_ADMIN,
    .module = &module_stage
};
NAKD_DECLARE_COMMAND(stage_set);

static struct nakd_command stage_current = {
    .name = "stage_current",
    .desc = "Returns current stage description.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"stage_current\", \"id\": 42}",
    .handler = cmd_stage_current,
    .access = ACCESS_ALL,
    .module = &module_stage
};
NAKD_DECLARE_COMMAND(stage_current);

static struct nakd_command stage_requested = {
    .name = "stage_requested",
    .desc = "Returns requested stage description.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"stage_requested\", \"id\": 42}",
    .handler = cmd_stage_requested,
    .access = ACCESS_ALL,
    .module = &module_stage
};
NAKD_DECLARE_COMMAND(stage_requested);

static struct nakd_command stage_status = {
    .name = "stage_status",
    .desc = "Returns information on stage change process.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"stage_current\", \"id\": 42}",
    .handler = cmd_stage_status,
    .access = ACCESS_ALL,
    .module = &module_stage
};
NAKD_DECLARE_COMMAND(stage_status);

static struct nakd_command stage_list = {
    .name = "stage_list",
    .desc = "Returns an array of available stages.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"stage_list\", \"id\": 42}",
    .handler = cmd_stage_list,
    .access = ACCESS_ALL,
    .module = &module_stage
};
NAKD_DECLARE_COMMAND(stage_list);
