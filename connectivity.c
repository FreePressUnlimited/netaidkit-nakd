#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <json-c/json.h>
#include "connectivity.h"
#include "event.h"
#include "timer.h"
#include "netintf.h"
#include "wlan.h"
#include "log.h"
#include "module.h"
#include "workqueue.h"
#include "shell.h"
#include "jsonrpc.h"
#include "command.h"
#include "nak_mutex.h"

#define CONNECTIVITY_SCRIPT_PATH(zone) NAKD_SCRIPT_PATH "connectivity/" zone
#define GW_ARPING_SCRIPT NAKD_SCRIPT("util/arping_gateway.sh")
#define GW_IP_SCRIPT NAKD_SCRIPT("util/gateway_ip.sh")
#define CONNECTIVITY_UPDATE_INTERVAL 20000 /* ms */

static pthread_mutex_t _connectivity_mutex;
static struct nakd_timer *_connectivity_update_timer;

static int _connectivity_local = 0;
static int _connectivity_internet = 0;
static pthread_mutex_t _connectivity_status_mutex;

#define CONNECTIVITY_STRING_ENTRY(state) [state] = #state
const char *nakd_connectivity_string[] = {
    CONNECTIVITY_STRING_ENTRY(CONNECTIVITY_NONE),
    CONNECTIVITY_STRING_ENTRY(CONNECTIVITY_LOCAL),
    CONNECTIVITY_STRING_ENTRY(CONNECTIVITY_INTERNET),
};

static int _arping_gateway(enum nakd_interface_id intf) {
    int status;
    nakd_log_execution_point();

    status = nakd_shell_exec(NAKD_SCRIPT_PATH,
         NULL, 10, 15, GW_ARPING_SCRIPT " %s",
                   nakd_interface_name(intf));
    /* 
     * arping refused to terminate itself after a specified timeout, most
     * likely waiting for some syscall to complete. Return OK for now and
     * count for the next call to return proper results.
     */
    if (status == -1)
        return 0;
    return status;
}

static char *_gateway_ip(void) {
    char *ip = NULL;
    nakd_assert(nakd_shell_exec(NAKD_SCRIPT_PATH, &ip, 10, 15, GW_IP_SCRIPT) >= 0);
    return ip;
}

static void _update_status(void) {
    nakd_log(L_DEBUG, "Updating local connectivity status...");
    int local = nakd_local_connectivity();
    nakd_log(L_DEBUG, "Updating Internet connectivity status...");
    int internet = nakd_internet_connectivity();

    nakd_mutex_lock(&_connectivity_status_mutex);
    _connectivity_local = local;
    _connectivity_internet = internet; 
    pthread_mutex_unlock(&_connectivity_status_mutex);
}

static void _connectivity_update(void *priv) {
    nakd_mutex_lock(&_connectivity_mutex);

    if (nakd_wlan_connecting()) {
        nakd_log(L_DEBUG, "Connecting to wireless network, connectivity update"
                                                                  " skipped.");
        goto unlock;
    }

    int wlan_connected = nakd_wlan_connected();
    if (wlan_connected == -1) {
        nakd_log(L_CRIT, "Can't query WLAN interface UCI configuration.");
        goto unlock;
    } 

    /* prefer ethernet */
    int ethernet_wan_connected = nakd_carrier_present(NAKD_WAN);
    if (ethernet_wan_connected == 1) {
        nakd_event_push(CONNECTIVITY_OK);
        if (nakd_wlan_connected())
            nakd_wlan_disconnect();
        goto unlock; 
    } else if (!ethernet_wan_connected) {
        if (!wlan_connected)
            nakd_event_push(CONNECTIVITY_LOST);
    }

    if (wlan_connected) {
        /* let things settle before probing network connectivity */
        int uptime = nakd_wlan_connection_uptime();
        if (uptime && uptime < 15)
            goto unlock;

        char *gw_ip = _gateway_ip(); 
        nakd_log(L_DEBUG, "ARP-pinging the default gateway: %s", gw_ip);
        free(gw_ip);

        if (!_arping_gateway(NAKD_WLAN)) {
            nakd_log(L_DEBUG, "Gateway responsive.");
            goto unlock;
        } else {
            nakd_log(L_INFO, "Default gateway doesn't respond to ARP"
                       " ping - checking if it's still in range...");

            json_object *jcurrent = nakd_wlan_current();
            if (jcurrent != NULL) {
                const char *current_ssid = nakd_net_ssid(jcurrent);
                nakd_wlan_set_autoconnect(current_ssid, 0);
                nakd_wlan_disconnect();
            }
            json_object_put(jcurrent);
        }
    }

    nakd_log(L_INFO, "No Ethernet or wireless connection.");

    if (!nakd_wlan_stored_netcount()) {
        nakd_log(L_INFO, "No WLAN candidates.");
        goto unlock;
    }

    nakd_log(L_INFO, "Looking for a WLAN candidate.");
    nakd_wlan_scan();

    json_object *jnetwork = nakd_wlan_candidate();
    if (jnetwork == NULL) {
        nakd_log(L_INFO, "No available known wireless networks");
        if (wlan_connected)
            nakd_event_push(CONNECTIVITY_LOST);
        goto unlock;
    } 

    const char *ssid = nakd_net_ssid(jnetwork);
    nakd_log(L_INFO, "Connecting to wireless network \"%s\"", ssid);
    if (!nakd_wlan_connect(jnetwork)) {
        nakd_log(L_INFO, "Wireless connection configured, ssid: \"%s\"", ssid);
        nakd_event_push(CONNECTIVITY_OK);
    }
    json_object_put(jnetwork);

unlock:
    _update_status();
    pthread_mutex_unlock(&_connectivity_mutex);
}

static struct work_desc _update_desc = {
    .impl = _connectivity_update,
    .name = "connectivity update",
    .timeout = 20
};

static void _connectivity_update_sighandler(siginfo_t *timer_info,
                                       struct nakd_timer *timer) {
    nakd_log_timer(timer);

    /* skip, if there's already a pending update in the workqueue */
    if (!nakd_work_pending(nakd_wq, _update_desc.name)) {
        struct work *work = nakd_alloc_work(&_update_desc);
        nakd_workqueue_add(nakd_wq, work);
    } else {
        nakd_log(L_DEBUG, "There's already connectivity update job in the"
                                                 " workqueue. Skipping.");
    }
}

static void _event_handler(enum nakd_event event, void *priv) {
    if (event == ETHERNET_WAN_PLUGGED) {
        nakd_event_push(CONNECTIVITY_OK);
        if (nakd_wlan_connected())
            nakd_wlan_disconnect();
    } else if (event == ETHERNET_WAN_LOST) {
        nakd_event_push(CONNECTIVITY_LOST);
    }
}

static int _connectivity_init(void) {
    pthread_mutex_init(&_connectivity_mutex, NULL);
    pthread_mutex_init(&_connectivity_status_mutex, NULL);

    nakd_event_add_handler(ETHERNET_WAN_PLUGGED, _event_handler, NULL);
    nakd_event_add_handler(ETHERNET_WAN_LOST, _event_handler, NULL);

    _connectivity_update_timer = nakd_timer_add(CONNECTIVITY_UPDATE_INTERVAL,
                      _connectivity_update_sighandler, NULL, "connectivity");

    struct work *update = nakd_alloc_work(&_update_desc);
    nakd_workqueue_add(nakd_wq, update);
    return 0;
}

static int _connectivity_cleanup(void) {
    nakd_timer_remove(_connectivity_update_timer);
    pthread_mutex_destroy(&_connectivity_status_mutex);
    pthread_mutex_destroy(&_connectivity_mutex);
    return 0;
}

static int _run_scripts_cb(const char *path, void *priv) {
    /* negated exit code - stop traversal if just one script exited with 0 */
    return !nakd_shell_exec(NAKD_SCRIPT_PATH, NULL, 10, 15, path);
}

/* returns 1 if just one script returns with 0 exit status */
static int _run_connectivity_scripts(const char *dirpath) {
    /* will return 0 if every script failed */
    return nakd_traverse_directory(dirpath, _run_scripts_cb, NULL);
}

int nakd_local_connectivity(void) {
    if (nakd_carrier_present(NAKD_WAN))
        return 1;
    if (nakd_wlan_connected())
        return !_arping_gateway(NAKD_WLAN);
    return 0;
}

int nakd_internet_connectivity(void) {
    if (!nakd_local_connectivity())
        return 0;
    return _run_connectivity_scripts(CONNECTIVITY_SCRIPT_PATH("internet"));
}

enum nakd_connectivity nakd_connectivity(void) {
    if (_connectivity_internet)
        return CONNECTIVITY_INTERNET;
    if (_connectivity_local)
        return CONNECTIVITY_LOCAL;
    return CONNECTIVITY_NONE;
}

static struct nakd_module module_connectivity = {
    .name = "connectivity",
    .deps = (const char *[]){ "workqueue", "event", "timer", "netintf", "wlan",
                        "notification" /* event handlers */, "command", NULL },
    .init = _connectivity_init,
    .cleanup = _connectivity_cleanup 
};
NAKD_DECLARE_MODULE(module_connectivity);

json_object *cmd_connectivity(json_object *jcmd, void *arg) {
    json_object *jresponse;

    if ((jresponse = nakd_command_timedlock(jcmd, &_connectivity_status_mutex))
                                                                     != NULL) {
        goto response;
    }

    json_object *jresult = json_object_new_object();
    json_object *jlocal = json_object_new_boolean(_connectivity_local);
    json_object *jinternet = json_object_new_boolean(_connectivity_internet);

    pthread_mutex_unlock(&_connectivity_status_mutex);

    json_object_object_add(jresult, "local", jlocal);
    json_object_object_add(jresult, "internet", jinternet);

    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);

response:
    return jresponse;
}

static struct nakd_command connectivity = {
    .name = "connectivity",
    .desc = "Connectivity status - local: gateway, internet: probabilistic"
                   "based on a group of services that should be reachable "
                                                  "anywhere in the world.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"connectivity\", \"id\": 42}",
    .handler = cmd_connectivity,
    .access = ACCESS_ALL,
    .module = &module_connectivity
};
NAKD_DECLARE_COMMAND(connectivity);
