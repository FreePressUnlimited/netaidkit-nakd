#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <string.h>
#include <json-c/json.h>
#include <iwinfo.h>
#include "wlan.h"
#include "ubus.h"
#include "log.h"
#include "module.h"
#include "jsonrpc.h"
#include "json.h"
#include "netintf.h"
#include "shell.h"
#include "workqueue.h"
#include "event.h"
#include "iwinfo_cli.h"

#define WLAN_NETWORK_LIST_PATH "/etc/nakd/wireless_networks"

#define WLAN_UPDATE_SCRIPT NAKD_SCRIPT("util/wlan_restart.sh")

#define WLAN_SCAN_SERVICE "iwinfo"
#define WLAN_SCAN_METHOD "scan"

#define WLAN_DEFAULT_INTERFACE "wlan0"
#define WLAN_AP_DEFAULT_INTERFACE "wlan0"

static pthread_mutex_t _wlan_mutex;

static const char *_wlan_interface_name;
static const char *_ap_interface_name;

static json_object *_wireless_networks;
static time_t _last_scan;

static json_object *_stored_networks;
static json_object *_current_network;
time_t _connected_timestamp;

int nakd_wlan_connection_uptime(void) {
    int uptime;
    pthread_mutex_lock(&_wlan_mutex);
    if (_connected_timestamp)
        uptime = time(NULL) - _connected_timestamp + 1;
    else
        uptime = 0;
    pthread_mutex_unlock(&_wlan_mutex);
    return uptime;
}

const char *nakd_wlan_interface_name(void) {
    return _wlan_interface_name;
}

const char *nakd_ap_interface_name(void) {
    return _ap_interface_name;
}

static int __read_stored_networks(void) {
    int result = 0;

    FILE *fp = fopen(WLAN_NETWORK_LIST_PATH, "r");
    if (fp == NULL)
        return 1;

    /* TODO write nakd_json_parse_file, parse 4096b chunks. */
    const size_t networks_buffer_size = 262144;
    char *networks_buffer = malloc(networks_buffer_size);
    size_t size = fread(networks_buffer, 1, networks_buffer_size - 1, fp);
    networks_buffer[size] = 0;

    json_tokener *jtok = json_tokener_new();
    _stored_networks = json_tokener_parse_ex(jtok, networks_buffer, size);
    if (json_tokener_get_error(jtok) != json_tokener_success)
        result = 1;

    fclose(fp);
    json_tokener_free(jtok);
    free(networks_buffer);
    return result;
}

static void __init_stored_networks(void) {
    if (__read_stored_networks()) {
            _stored_networks = json_object_new_array();
    }

    nakd_log(L_INFO, "Read %d known networks.",
        json_object_array_length(_stored_networks)); 
}

static void __cleanup_stored_networks(void) {
    json_object_put(_stored_networks);
}

static int __save_stored_networks(void) {
    FILE *fp = fopen(WLAN_NETWORK_LIST_PATH, "w");
    if (fp == NULL)
        return 1;

    const char *networks = json_object_get_string(_stored_networks); 
    fwrite(networks, strlen(networks), 1, fp);
    fclose(fp);
    return 0;
}

const char *nakd_net_key(json_object *jnetwork) {
    return nakd_json_get_string(jnetwork, "key");
}

const char *nakd_net_ssid(json_object *jnetwork) {
    return nakd_json_get_string(jnetwork, "ssid");
}

int nakd_net_hidden(json_object *jnetwork) {
    int hidden = nakd_json_get_int(jnetwork, "hidden");
    if (errno)
        return 0;
    return hidden;
}

static json_object *__get_stored_network(const char *ssid) {
    nakd_assert(_stored_networks != NULL);

    for (int i = 0; i < json_object_array_length(_stored_networks); i++) {
        json_object *jnetwork = json_object_array_get_idx(_stored_networks, i);
        const char *stored_ssid = nakd_net_ssid(jnetwork);

        if (stored_ssid == NULL) { 
            nakd_log(L_WARNING, "Malformed configuration file: " WLAN_NETWORK_LIST_PATH);
            continue;
        }

        if (!strcmp(stored_ssid, ssid))
            return jnetwork;
    } 
    return NULL;
}

static void __remove_stored_network(const char *ssid) {
    nakd_assert(_stored_networks != NULL);

    /* TODO json-c: currently there's no way to remove an array element,
     * recheck later or patch in json-c.
     */

    json_object *jupdated = json_object_new_array();

    for (int i = 0; i < json_object_array_length(_stored_networks); i++) {
        json_object *jnetwork = json_object_array_get_idx(_stored_networks, i);
        const char *stored_ssid = nakd_net_ssid(jnetwork);

        if (stored_ssid == NULL) { 
            nakd_log(L_WARNING, "Malformed configuration file: " WLAN_NETWORK_LIST_PATH);
            continue;
        }

        if (!strcmp(stored_ssid, ssid)) {
            continue;
        }

        json_object_array_add(jupdated, jnetwork);
    } 

    json_object_put(_stored_networks);
    _stored_networks = jupdated;

    if (__save_stored_networks())
        nakd_log(L_CRIT, "Couldn't remove stored network credentials: %s", ssid);
}

static json_object *__find_network(const char *ssid) {
    if (_wireless_networks == NULL)
        return NULL;

    for (int i = 0; i < json_object_array_length(_wireless_networks); i++) {
        json_object *jnetwork = json_object_array_get_idx(_wireless_networks, i);
        const char *issid = nakd_json_get_string(jnetwork, "ssid");
        nakd_assert(issid != NULL);

        if (!strcmp(issid, ssid))
            return jnetwork;
    }
    return NULL;
}

static json_object *_create_network_entry(const char *ssid, const char *key) {
    json_object *jnetwork = __find_network(ssid);
    if (jnetwork == NULL)
        return NULL;

    const char *enc = nakd_net_encryption(jnetwork);
    nakd_assert(enc != NULL); 

    json_object *jssid = json_object_new_string(ssid);
    json_object *jkey = key == NULL ? NULL : json_object_new_string(key);
    json_object *jenc = json_object_new_string(enc);

    json_object *jentry = json_object_new_object(); 
    json_object_object_add(jentry, "ssid", jssid);
    if (jkey != NULL)
        json_object_object_add(jentry, "key", jkey);
    json_object_object_add(jentry, "encryption", jenc);
    return jentry;
}

static int __store_network(const char *ssid, const char *key) {
    if (__get_stored_network(ssid) != NULL)
        __remove_stored_network(ssid);

    /*
     * Use just ssid and key from user-supplied network entry, copy
     * encryption type from _wireless_networks.
     */
    json_object *jentry = _create_network_entry(ssid, key);
    if (jentry == NULL)
        return 1;
    json_object_array_add(_stored_networks, jentry);

    if (__save_stored_networks()) {
        nakd_log(L_CRIT, "Couldn't store network credentials for %s", ssid);
        return 1;
    }
    return 0;
}

static int __forget_network(json_object *jnetwork) {
    const char *ssid = nakd_net_ssid(jnetwork);
    if (__get_stored_network(ssid) != NULL)
        __remove_stored_network(ssid);

    if (__save_stored_networks()) {
        nakd_log(L_CRIT, "Couldn't remove \"%s\" network.", ssid);
        return 1;
    }
    return 0;   
}

static int __in_range(const char *ssid) {
    if (_wireless_networks == NULL)
        return -1;

    for (int i = 0; i < json_object_array_length(_wireless_networks); i++) {
        json_object *jnetwork = json_object_array_get_idx(_wireless_networks, i);

        const char *iter_ssid = nakd_net_ssid(jnetwork);
        nakd_assert(iter_ssid != NULL);

        if (!strcmp(iter_ssid, ssid))
            return 1;
    }
    return 0;
}

int nakd_wlan_in_range(const char *ssid) {
    pthread_mutex_lock(&_wlan_mutex);
    int s = __in_range(ssid);
    pthread_mutex_unlock(&_wlan_mutex);
    return s;
}

static json_object *__choose_network(void) {
    if (_wireless_networks == NULL)
        return NULL;

    for (int i = 0; i < json_object_array_length(_wireless_networks); i++) {
        json_object *jnetwork = json_object_array_get_idx(_wireless_networks, i);

        const char *ssid = nakd_net_ssid(jnetwork);
        nakd_assert(ssid != NULL);

        json_object *jstored = __get_stored_network(ssid);
        if (jstored != NULL)
            return jstored;
    }
    return NULL;
}

json_object *nakd_wlan_candidate(void) {
    pthread_mutex_lock(&_wlan_mutex);
    json_object *jnetwork = __choose_network();
    pthread_mutex_unlock(&_wlan_mutex);
    return jnetwork;
}

int nakd_wlan_netcount(void) {
    pthread_mutex_lock(&_wlan_mutex);
    int count = _wireless_networks == NULL ? 0 :
        json_object_array_length(_wireless_networks);
    pthread_mutex_unlock(&_wlan_mutex);
    return count;
}

static void _wlan_update_cb(struct ubus_request *req, int type,
                                       struct blob_attr *msg) {
    json_tokener *jtok = json_tokener_new();

    char *json_str = blobmsg_format_json(msg, true);
    nakd_assert(json_str != NULL);
    if (strlen(json_str) <= 2)
        goto badmsg;

    json_object *jresponse = json_tokener_parse_ex(jtok, json_str, strlen(json_str));
    if (json_tokener_get_error(jtok) != json_tokener_success)
        goto badmsg;

    json_object *jstate = NULL;
    json_object_object_get_ex(jresponse, "results", &jstate); 
    if (jstate == NULL || json_object_get_type(jstate) != json_type_array)
        goto badmsg;

    if (!json_object_array_length(jstate)) {
        nakd_log(L_INFO, "Received an empty wireless network list, discarding.");
        goto cleanup;
    }

    pthread_mutex_lock(&_wlan_mutex);
    if (_wireless_networks != NULL)
        json_object_put(_wireless_networks);
    _wireless_networks = jstate;
    _last_scan = time(NULL);
    pthread_mutex_unlock(&_wlan_mutex);

    nakd_log(L_INFO, "Updated wireless network list. Available networks: %d",
                                                       nakd_wlan_netcount());
    goto cleanup;

badmsg:
    nakd_log(L_WARNING, "Got unusual response from " WLAN_SCAN_SERVICE 
                              " " WLAN_SCAN_METHOD ": %s.", json_str);
cleanup:
    free(json_str);
    json_tokener_free(jtok);
}

static int _wlan_scan_rpcd(void) {
    json_object *jparam = json_object_new_object();
    json_object *jdevice = json_object_new_string(_ap_interface_name);
    json_object_object_add(jparam, "device", jdevice);
    const char *param = json_object_get_string(jparam);

    int s = nakd_ubus_call(WLAN_SCAN_SERVICE, WLAN_SCAN_METHOD, param,
                                               _wlan_update_cb, NULL);
    json_object_put(jparam);
    /* returns UBUS_STATUS_ */
    return s;
}

struct iwinfo_scan_priv {
    const struct iwinfo_ops *iwctx;
    struct iwinfo_scanlist_entry *networks;
    int status;
};

static const char *_iwinfo_enc_format_uci(struct iwinfo_crypto_entry *c) {
    /* based on libiwinfo implementation */
    nakd_assert(c != NULL);
	if (c->enabled)
	{
		/* WEP */
		if (c->auth_algs && !c->wpa_version)
		{
            return "wep";
		}
		/* WPA */
		else if (c->wpa_version)
		{
			switch (c->wpa_version) {
				case 3:
                    return "psk-mixed";
				case 2:
                    return "psk2";
				case 1:
                    return "psk";
			}
		}
	}
    return "none";
}

static void _wlan_scan_iwinfo_work(void *priv) {
    const char *iwctx_ifname = _ap_interface_name;
    struct iwinfo_scan_priv *scan = priv;
    scan->status = 0;

    scan->iwctx = iwinfo_backend(iwctx_ifname);
    if (scan->iwctx == NULL) {
        nakd_log(L_WARNING, "Couldn't initialize iwinfo backend (intf: %s)",
                                                              iwctx_ifname);
        scan->status = 1;
        return;
    }

    /*
     * scanlist() can lock up the thread if there's another process using the
     * interface at the time. This problem might stem from intf backend, thus
     * it might not be fixable in libiwinfo.
     */
    int len;
    scan->networks = malloc(IWINFO_BUFSIZE);
    nakd_assert(scan->networks != NULL); 
    nakd_log(L_DEBUG, "Initialized libiwinfo context, calling iwctx->scanlist().");
    if (scan->iwctx->scanlist(iwctx_ifname, (void *)(scan->networks),
                                                             &len)) {
        nakd_log(L_CRIT, "Scanning not possible");
        scan->status = 1;
        return;
    } else if (len <= 0) {
        nakd_log(L_DEBUG, "No scan results");
        return;
    }

    nakd_log(L_DEBUG, "Processing scan results.");

    const int count = len/(sizeof(struct iwinfo_scanlist_entry));
    json_object *jresults = json_object_new_array();
    for (struct iwinfo_scanlist_entry *e = scan->networks;
                        e < scan->networks + count; e++) {
        json_object *jnetwork = json_object_new_object();

        json_object *jssid = json_object_new_string(e->ssid);
        json_object_object_add(jnetwork, "ssid", jssid); 

        json_object *jbssid = json_object_new_string(
                               format_bssid(e->mac));
        json_object_object_add(jnetwork, "bssid", jbssid);

        json_object *jchannel;
        if (e->channel > 0)
            jchannel = json_object_new_int(e->channel);
        else
            jchannel = json_object_new_string("unknown");
        json_object_object_add(jnetwork, "channel", jchannel); 

        json_object *jquality;
        if (e->quality > 0)
            jquality = json_object_new_int(e->quality);
        else
            jquality = json_object_new_string("unknown");
        json_object_object_add(jnetwork, "quality", jquality);

        json_object *jquality_max;
        if (e->quality_max > 0)
            jquality_max = json_object_new_int(e->quality_max);
        else
            jquality_max = json_object_new_string("unknown");
        json_object_object_add(jnetwork, "quality_max", jquality_max);

        json_object *jsignal = json_object_new_string(format_signal(
                                                e->signal - 0x100));
        json_object_object_add(jnetwork, "signal", jsignal);

        json_object *jencdesc = json_object_new_string(format_encryption(
                                                            &e->crypto));
        json_object_object_add(jnetwork, "encryption_desc", jencdesc);

        json_object *jencryption = json_object_new_string(
                      _iwinfo_enc_format_uci(&e->crypto));
        json_object_object_add(jnetwork, "encryption", jencryption);

        json_object_array_add(jresults, jnetwork);
    }

    if (_wireless_networks != NULL)
        json_object_put(_wireless_networks);
    _wireless_networks = jresults;
    _last_scan = time(NULL);
} 

static void _cleanup_iwinfo_scan(struct iwinfo_scan_priv *scan) {
    if (scan->networks != NULL)
        free(scan->networks);
    if (scan->iwctx != NULL)
        iwinfo_finish();

    scan->networks = NULL;
    scan->iwctx = NULL;
}

static void _wlan_scan_iwinfo_canceled(void *priv) {
    struct iwinfo_scan_priv *scan = priv;

    nakd_log(L_INFO, "libiwinfo wireless network scan canceled, cleaning up.");
    _cleanup_iwinfo_scan(scan);
} 

static struct iwinfo_scan_priv _iwinfo_scan_priv;
static struct work_desc _iwinfo_scan_desc = {
    .impl = _wlan_scan_iwinfo_work,
    .canceled = _wlan_scan_iwinfo_canceled,
    .name = "wlan scan",
    .synchronous = 1,
    .timeout = 10,
    .priv = &_iwinfo_scan_priv
};

static int _wlan_scan_iwinfo(void) {
    int status;
    struct work *scan_wq_entry = nakd_alloc_work(&_iwinfo_scan_desc);

    pthread_mutex_lock(&_wlan_mutex);
    nakd_workqueue_add(nakd_wq, scan_wq_entry);
    if (scan_wq_entry->status == WORK_CANCELED) {
        status = 1;
        goto unlock;
    }

    status = _iwinfo_scan_priv.status;
    _cleanup_iwinfo_scan(&_iwinfo_scan_priv);

unlock:
    pthread_mutex_unlock(&_wlan_mutex);
    nakd_free_work(scan_wq_entry);
    return status;
}

int nakd_wlan_scan(void) {
    nakd_log(L_INFO, "Scanning for wireless networks."); 
    _wlan_scan_iwinfo();
}

const char *nakd_net_encryption(json_object *jnetwork) {
    return nakd_json_get_string(jnetwork, "encryption");
}

int nakd_net_disabled(json_object *jnetwork) {
    int disabled = nakd_json_get_int(jnetwork, "disabled");
    if (errno)
        return 0;
    return disabled;
}

static int _update_wlan_config_ssid(struct uci_option *option, void *priv) {
    struct interface *intf = priv;
    struct uci_section *ifs = option->section;
    struct uci_context *ctx = ifs->package->ctx;
    struct uci_package *pkg = ifs->package;
    json_object *jnetwork = priv;     

    const char *pkg_name = pkg->e.name;
    const char *section_name = ifs->e.name;

    const char *ssid = nakd_net_ssid(jnetwork);
    nakd_assert(ssid != NULL);
    struct uci_ptr ssid_ptr = {
        .package = pkg_name,
        .section = section_name,
        .option = "ssid",
        .value = ssid 
    };
    /* this function is called from nakd_uci_, no locking required for uci_set */
    nakd_uci_set_nolock(&ssid_ptr);

    const char *encryption = nakd_net_encryption(jnetwork);
    nakd_assert(encryption != NULL); /* see: _validate_*_config */

    if (strcmp("none", encryption)) {
        const char *key = nakd_net_key(jnetwork);
        if (key != NULL) {
            struct uci_ptr key_ptr = {
                .package = pkg_name,
                .section = section_name,
                .option = "key",
                .value = key
            };
            nakd_uci_set_nolock(&key_ptr);
        } else {
            nakd_log(L_CRIT, "Encryption set, but no passphrase. "
                                 "Configuration left unchanged.");
            return 1;
        }
    }

    struct uci_ptr enc_ptr = {
        .package = pkg_name,
        .section = section_name,
        .option = "encryption",
        .value = encryption
    };
    nakd_uci_set_nolock(&enc_ptr);

    int disabled = nakd_net_disabled(jnetwork);
    if (disabled != -1) {
        struct uci_ptr disabled_ptr = {
            .package = pkg_name,
            .section = section_name,
            .option = "disabled",
            .value = disabled ? "1" : "0"
        };
        nakd_uci_set_nolock(&disabled_ptr);
    }

    int hidden = nakd_net_hidden(jnetwork);
    if (hidden != -1) {
        struct uci_ptr hidden_ptr = {
            .package = pkg_name,
            .section = section_name,
            .option = "hidden",
            .value = hidden ? "1" : "0"
        };
        nakd_uci_set_nolock(&hidden_ptr);
    }
    return 0;
}

static int _reload_wireless_config(void) {
    int status = 0;

    /* avoid spurious state updates */
    nakd_netintf_disable_updates(5);

    nakd_log(L_INFO, "Restarting WLAN.");
    char *output;
    if (nakd_shell_exec(NAKD_SCRIPT_PATH, &output, WLAN_UPDATE_SCRIPT)) {
        nakd_log(L_CRIT, "Error while running " WLAN_UPDATE_SCRIPT);
        status = 1;
        goto unlock;
    }

    nakd_log(L_DEBUG, WLAN_UPDATE_SCRIPT " output: %s", output);
    free(output);

unlock:
    return status;
}

static void __swap_current_network(json_object *jnetwork) {
    if (_current_network != NULL)
        json_object_put(_current_network);
    if (jnetwork != NULL)
        json_object_get(jnetwork);
    _current_network = jnetwork;
}

json_object *nakd_wlan_current(void) {
    pthread_mutex_lock(&_wlan_mutex);
    if (_current_network != NULL)
        json_object_get(_current_network);
    json_object *jnetwork = _current_network;
    pthread_mutex_unlock(&_wlan_mutex);
    return jnetwork;
}

static int _wlan_connect(json_object *jnetwork) {
    const char *ssid = nakd_net_ssid(jnetwork);
    const char *key = nakd_net_key(jnetwork);
    if (ssid == NULL || key == NULL)
        return 1;

    /* TODO revisit.
     * Probably an OpenWRT bug: dirty configuration prevents hostapd from
     * starting if interfaces share the same phy.
     */
    int in_range = __in_range(ssid);
    if (!in_range) {
        nakd_log(L_NOTICE, "Network \"%s\" is not in range.", ssid);
        return 1;
    } else if (in_range == -1) {
        nakd_log(L_NOTICE, "Please scan before connecting!");
        return 1;
    }

    nakd_log(L_INFO, "Connecting to \"%s\" wireless network.", ssid);
    nakd_log(L_INFO, "Updating WLAN configuration.");

    /* Continue if exactly one UCI section was found and updated. */
    if (nakd_update_iface_config(NAKD_WLAN, _update_wlan_config_ssid,
                                                    jnetwork) != 1) {
        return 1;
    }

    __swap_current_network(jnetwork);
    _connected_timestamp = time(NULL);
    return _reload_wireless_config();
}

static int _validate_ap_config(json_object *jnetwork) {
    const char *key = nakd_net_key(jnetwork);
    const char *ssid = nakd_net_ssid(jnetwork);

    if (key == NULL || ssid == NULL ||
        nakd_net_disabled(jnetwork) == -1 ||
        nakd_net_hidden(jnetwork) == -1 ||
        nakd_net_encryption(jnetwork) == NULL)
        return 1;

    return strlen(key) > 8 && strlen(key) <= 64 &&
           strlen(ssid) <= 32;
}

static int _validate_wlan_config(json_object *jnetwork) {
    return nakd_net_ssid(jnetwork) == NULL ||
           nakd_net_encryption(jnetwork) == NULL;
}

static int _configure_ap(json_object *jnetwork) {
    /* Continue if exactly one UCI section was found and updated. */
    if (nakd_update_iface_config(NAKD_AP, _update_wlan_config_ssid,
                                                  jnetwork) != 1) {
        return 1;
    }
    return _reload_wireless_config();
}

int nakd_wlan_connect(json_object *jnetwork) {
    pthread_mutex_lock(&_wlan_mutex);
    int status = _wlan_connect(jnetwork);
    pthread_mutex_unlock(&_wlan_mutex);
    return status;
}

int nakd_wlan_disconnect(void) {
    int status = 0;

    nakd_log(L_INFO, "Disabling WLAN.");
    pthread_mutex_lock(&_wlan_mutex);

    if (nakd_disable_interface(NAKD_WLAN)) {
        status = 1;
        goto unlock;
    }

    _connected_timestamp = 0;
    __swap_current_network(NULL);
    status = _reload_wireless_config();

unlock:
    pthread_mutex_unlock(&_wlan_mutex);
    return status;
}

static int _wlan_init(void) {
    pthread_mutex_init(&_wlan_mutex, NULL);
    if ((_wlan_interface_name = nakd_interface_name(NAKD_WLAN)) == NULL) {
        nakd_log(L_WARNING, "Couldn't get %s interface name from UCI, "
                     "continuing with default " WLAN_DEFAULT_INTERFACE,
                                       nakd_interface_type[NAKD_WLAN]);
        _wlan_interface_name = WLAN_DEFAULT_INTERFACE;
    }

    if ((_ap_interface_name = nakd_interface_name(NAKD_AP)) == NULL) {
        nakd_log(L_WARNING, "Couldn't get %s interface name from UCI, "
                     "continuing with default " WLAN_DEFAULT_INTERFACE,
                                         nakd_interface_type[NAKD_AP]);
        _wlan_interface_name = WLAN_AP_DEFAULT_INTERFACE;
    }

    __init_stored_networks();

    /* An out-of-range wireless network can cause erratic AP interface
     * operation if both interfaces are one the same chip, as in ar71xx case.
     *
     * This may be an OpenWRT or hardware issue.
     */
    nakd_wlan_disconnect();

    return 0;
}

static int _wlan_cleanup(void) {
    __cleanup_stored_networks();
    pthread_mutex_destroy(&_wlan_mutex);
    return 0;
}

json_object *cmd_wlan_list(json_object *jcmd, void *arg) {
    json_object *jresponse;

    pthread_mutex_lock(&_wlan_mutex);
    if (_wireless_networks == NULL) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                           "Internal error - no cached scan results,"
                                           " call wlan_scan first.");
        goto unlock;
    }

    jresponse = nakd_jsonrpc_response_success(jcmd,
           nakd_json_deepcopy(_wireless_networks));

unlock:
    pthread_mutex_unlock(&_wlan_mutex);
    return jresponse;
}

json_object *cmd_wlan_list_stored(json_object *jcmd, void *arg) {
    json_object *jresponse;

    pthread_mutex_lock(&_wlan_mutex);
    jresponse = nakd_jsonrpc_response_success(jcmd,
             nakd_json_deepcopy(_stored_networks));

unlock:
    pthread_mutex_unlock(&_wlan_mutex);
    return jresponse;
}

json_object *cmd_wlan_scan(json_object *jcmd, void *arg) {
    json_object *jresponse;

    if (nakd_wlan_scan()) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
           "Internal error - couldn't update wireless network list");
        return jresponse;
    }

    int netcount = nakd_wlan_netcount();

    json_object *jresult = json_object_new_object();
    json_object *jnetcount = json_object_new_int(netcount);
    json_object *jlastscan = json_object_new_int(_last_scan);
    json_object_object_add(jresult, "netcount", jnetcount);
    json_object_object_add(jresult, "last_scan", jlastscan);

    return nakd_jsonrpc_response_success(jcmd, jresult);
}

json_object *cmd_wlan_connect(json_object *jcmd, void *arg) {
    json_object *jresponse;
    json_object *jparams;

    pthread_mutex_lock(&_wlan_mutex);

    if ((jparams = nakd_jsonrpc_params(jcmd)) == NULL ||
        json_object_get_type(jparams) != json_type_object) {
        goto params;
    }

    if (_validate_wlan_config(jparams))
        goto params;

    json_object *jstore = NULL;
    json_object_object_get_ex(jparams, "store", &jstore);
    if (jstore != NULL) {
       if (json_object_get_type(jstore) != json_type_boolean) {
            jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
                       "Invalid request - \"store\" parameter must be of "
                                                          "boolean type");
            goto unlock;
       }
    }

    if (_wireless_networks == NULL) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                           "Internal error - no cached scan results,"
                                           " call wlan_scan first.");
        goto unlock;
    }

    const char *ssid = nakd_net_ssid(jparams);
    const char *key = nakd_net_key(jparams);
    if (ssid == NULL)
        goto params;

    if (_wlan_connect(jparams)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                 "Internal error - couldn't connect to the network");
        goto unlock;
    }

    nakd_event_push(CONNECTIVITY_OK);

    if (jstore != NULL) {
       if (json_object_get_boolean(jstore)) {
           if (__store_network(ssid, key)) {
                jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                      "Internal error - couldn't store network credentials. "
                                                               "Connected.");
                goto unlock;
           }
       }
    }

    json_object *jresult = json_object_new_string("OK");
    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);
    goto unlock;

params:
    jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_PARAMS,
                "Invalid parameters - params should be an object"
                           " with \"ssid\" and \"key\" members");
unlock:
    pthread_mutex_unlock(&_wlan_mutex);
    return jresponse;
}

json_object *cmd_configure_ap(json_object *jcmd, void *arg) {
    json_object *jparams;
    json_object *jresponse;
    pthread_mutex_lock(&_wlan_mutex);

    if ((jparams = nakd_jsonrpc_params(jcmd)) == NULL ||
        json_object_get_type(jparams) != json_type_object) {
        goto params;
    }

    /* force encryption to psk2 */
    json_object_object_del(jparams, "encryption");
    json_object *jencryption = json_object_new_string("psk2");
    json_object_object_add(jparams, "encryption", jencryption);

    if (_validate_ap_config(jparams))
        goto params;

    if (_configure_ap(jparams)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                "Internal error - couldn't configure access point.");
        goto unlock;
    }

    json_object *jresult = json_object_new_string("OK");
    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);
    goto unlock;

params:
    jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_PARAMS,
           "Invalid parameters - params should be an object with"
           " \"ssid\", \"key\", \"encryption\", and \"disabled\""
                                                    " members.");
unlock:
    pthread_mutex_unlock(&_wlan_mutex);
    return jresponse;
}

json_object *cmd_wlan_forget(json_object *jcmd, void *arg) {
    json_object *jparams;
    json_object *jresponse;
    pthread_mutex_lock(&_wlan_mutex);

    if ((jparams = nakd_jsonrpc_params(jcmd)) == NULL ||
        json_object_get_type(jparams) != json_type_object) {
        goto params;
    }

    if (__forget_network(jparams)) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
                     "Internal error - couldn't save network list.");
        goto unlock;
    }

    json_object *jresult = json_object_new_string("OK");
    jresponse = nakd_jsonrpc_response_success(jcmd, jresult);
    goto unlock;

params:
    jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_PARAMS,
           "Invalid parameters - params should be an object with"
                                           " \"ssid\", member.");
unlock:
    pthread_mutex_unlock(&_wlan_mutex);
    return jresponse;
}

static int _get_current_wlan_config(struct uci_option *option, void *priv) {
    json_object **jnetwork = priv;
    /* in case there are two sections with WLAN tag */
    if (*jnetwork != NULL)
        return 1;

    struct uci_section *ifs = option->section;
    struct uci_context *ctx = ifs->package->ctx;
    struct uci_package *pkg = ifs->package;

    json_object *jssid = NULL;
    json_object *jenc = NULL;
    json_object *jdisabled = NULL;
    json_object *jhidden = NULL;

    struct uci_ptr ssid_ptr = {
        .package = pkg->e.name,
        .section = ifs->e.name,
        .option = "ssid" 
    };
    if (uci_lookup_ptr(ctx, &ssid_ptr, NULL, 0) == UCI_OK)
        jssid = json_object_new_string(ssid_ptr.o->v.string);
    else
        nakd_log(L_DEBUG, "Couldn't get \"ssid\"");

    struct uci_ptr enc_ptr = {
        .package = pkg->e.name,
        .section = ifs->e.name,
        .option = "encryption" 
    };
    if (uci_lookup_ptr(ctx, &enc_ptr, NULL, 0) == UCI_OK)
        jenc = json_object_new_string(enc_ptr.o->v.string);
    else
        nakd_log(L_DEBUG, "Couldn't get \"encryption\"");

    struct uci_ptr disabled_ptr = {
        .package = pkg->e.name,
        .section = ifs->e.name,
        .option = "disabled" 
    };
    if (uci_lookup_ptr(ctx, &disabled_ptr, NULL, 0) == UCI_OK)
        jdisabled = json_object_new_string(disabled_ptr.o->v.string);
    else
        nakd_log(L_DEBUG, "Couldn't get \"disabled\"");

    struct uci_ptr hidden_ptr = {
        .package = pkg->e.name,
        .section = ifs->e.name,
        .option = "hidden" 
    };
    if (uci_lookup_ptr(ctx, &hidden_ptr, NULL, 0) == UCI_OK)
        jhidden = json_object_new_string(hidden_ptr.o->v.string);
    else
        nakd_log(L_DEBUG, "Couldn't get \"hidden\"");

    *jnetwork = json_object_new_object();
    if (jssid != NULL)
        json_object_object_add(*jnetwork, "ssid", jssid);
    if (jenc != NULL)
        json_object_object_add(*jnetwork, "encryption", jenc);
    if (jdisabled != NULL)
        json_object_object_add(*jnetwork, "disabled", jdisabled);
    if (jhidden != NULL)
        json_object_object_add(*jnetwork, "hidden", jhidden);
    return 0;
}

json_object *cmd_wlan_current(json_object *jcmd, void *arg) {
    json_object *jresponse;
    json_object *jparams;

    pthread_mutex_lock(&_wlan_mutex);

    if ((jparams = nakd_jsonrpc_params(jcmd)) == NULL ||
        json_object_get_type(jparams) != json_type_string) {
        goto params;
    }

    const char *ifacestr = json_object_get_string(jparams);
    enum nakd_interface iface = nakd_iface_from_string(ifacestr);
    if (iface != NAKD_WLAN && iface != NAKD_AP)
        goto params;

    json_object *jnetwork = NULL;
    if (nakd_update_iface_config(iface, _get_current_wlan_config,
                                               &jnetwork) != 1) {
        jresponse = nakd_jsonrpc_response_error(jcmd, INTERNAL_ERROR,
           "Internal error - couldn't get interface configuration.");
        goto unlock;
    }

    jresponse = nakd_jsonrpc_response_success(jcmd, jnetwork);
    goto unlock;

params:
    jresponse = nakd_jsonrpc_response_error(jcmd, INVALID_REQUEST,
           "Invalid request - params should be a string; \"WLAN\""
                                "and \"AP\" interfaces allowed.");
unlock:
    pthread_mutex_unlock(&_wlan_mutex);
    return jresponse;
}

static struct nakd_module module_wlan = {
    .name = "wlan",
    .deps = (const char *[]){ "uci", "ubus", "netintf", "workqueue", NULL },
    .init = _wlan_init,
    .cleanup = _wlan_cleanup 
};
NAKD_DECLARE_MODULE(module_wlan);

static struct nakd_command wlan_connect = {
    .name = "wlan_connect",
    .desc = "Connects to a wireless network. Can store network credentials.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"wlan_connect\", \"params\":"
                "{\"ssid\": \"network SSID\", \"key\": \"network passphrase\","
                                                  "\"store\": 1}, \"id\": 42}",
    .handler = cmd_wlan_connect,
    .access = ACCESS_USER,
    .module = &module_wlan
};
NAKD_DECLARE_COMMAND(wlan_connect);

static struct nakd_command wlan_scan = {
    .name = "wlan_scan",
    .desc = "Triggers wireless network scan. Does not return results.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"wlan_scan\", \"id\": 42}",
    .handler = cmd_wlan_scan,
    .access = ACCESS_ROOT,
    .module = &module_wlan
};
NAKD_DECLARE_COMMAND(wlan_scan);

static struct nakd_command wlan_list = {
    .name = "wlan_list",
    .desc = "Returns cached wireless network list.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"wlan_list\", \"id\": 42}",
    .handler = cmd_wlan_list,
    .access = ACCESS_USER,
    .module = &module_wlan
};
NAKD_DECLARE_COMMAND(wlan_list);

static struct nakd_command wlan_list_stored = {
    .name = "wlan_list_stored",
    .desc = "Returns a list of known networks.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"wlan_list_stored\", \"id\": 42}",
    .handler = cmd_wlan_list_stored,
    .access = ACCESS_USER,
    .module = &module_wlan
};
NAKD_DECLARE_COMMAND(wlan_list_stored);

static struct nakd_command configure_ap = {
    .name = "configure_ap",
    .desc = "Configures the access point.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"configure_ap\", \"params\":"
         " {\"ssid\": \"AP SSID\", \"key\": \"...\", \"encryption\": \"psk2\","
                               " \"disabled\": 0, \"hidden\": 0}, \"id\": 42}",
    .handler = cmd_configure_ap,
    .access = ACCESS_USER,
    .module = &module_wlan
};
NAKD_DECLARE_COMMAND(configure_ap);

static struct nakd_command wlan_forget = {
    .name = "wlan_forget",
    .desc = "Makes nakd forget a wireless network.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"wlan_forget\", \"params\":"
                                          " {\"ssid\": \"...\"}, \"id\": 42}",
    .handler = cmd_wlan_forget,
    .access = ACCESS_USER,
    .module = &module_wlan
};
NAKD_DECLARE_COMMAND(wlan_forget);

static struct nakd_command wlan_current = {
    .name = "wlan_current",
    .desc = "Shows current wireless interface configuration.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"wlan_current\", \"params\":"
                                                      " \"WLAN\", \"id\": 42}",
    .handler = cmd_wlan_current,
    .access = ACCESS_USER,
    .module = &module_wlan
};
NAKD_DECLARE_COMMAND(wlan_current);
