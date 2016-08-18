#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <json-c/json.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include "netintf.h"
#include "jsonrpc.h"
#include "json.h"
#include "log.h"
#include "timer.h"
#include "event.h"
#include "nak_uci.h"
#include "module.h"
#include "workqueue.h"
#include "command.h"
#include "misc.h"
#include "thread.h"

/* eg. "option nak_lan_tag 1" for wired lan interface */
const char *nakd_uci_interface_tag[] = {
    [NAKD_LAN] = "nak_lan_tag",
    [NAKD_WAN] = "nak_wan_tag",
    [NAKD_WLAN] = "nak_wlan_tag",
    [NAKD_AP] = "nak_ap_tag",
    [NAKD_INTF_MAX] = NULL
};

const char *nakd_interface_type[] = {
    [NAKD_LAN] = "LAN",
    [NAKD_WAN] = "WAN",
    [NAKD_WLAN] = "WLAN",
    [NAKD_AP] = "AP",
    [NAKD_INTF_MAX] = NULL
};

const char *nakd_interface_default[] = {
    [NAKD_LAN] = "eth1",
    [NAKD_WAN] = "eth0",
    [NAKD_WLAN] = "wlan0",
    [NAKD_AP] = "wlan1",
    [NAKD_INTF_MAX] = NULL
};

static struct nakd_thread *_netlink_thread;
static struct nl_cache_mngr *_manager;
static struct nl_cache *_cache;
static int _shutdown;

static pthread_mutex_t _netintf_mutex;

static struct nakd_interface _interfaces[] = {
    {
        .id = NAKD_LAN,

        .carrier_up_event = ETHERNET_LAN_PLUGGED,
        .carrier_down_event = ETHERNET_LAN_LOST,
    },
    {
        .id = NAKD_WAN,

        .carrier_up_event = ETHERNET_WAN_PLUGGED,
        .carrier_down_event = ETHERNET_WAN_LOST
    },
    {
        .id = NAKD_WLAN 
    },
    {
        .id = NAKD_AP
    }
};

static void _carrier_update(struct nakd_interface *iface,
                                struct rtnl_link *link) {
    const char *link_name = rtnl_link_get_name(link);

    int previous_carrier_state = iface->carrier_state;
    int current_carrier_state = rtnl_link_get_carrier(link);

    if (!previous_carrier_state && current_carrier_state) {
        if (iface->carrier_down_event != EVENT_UNSPECIFIED)
            nakd_event_push(iface->carrier_down_event);
        nakd_log(L_DEBUG, "%s: carrier went down.", link_name);
    } else if (previous_carrier_state && !current_carrier_state) {
        if (iface->carrier_up_event != EVENT_UNSPECIFIED)
            nakd_event_push(iface->carrier_up_event);
        nakd_log(L_DEBUG, "%s: carrier went up.", link_name);
    }

    iface->carrier_state = current_carrier_state; 
}

typedef void (*intf_update_cb)(struct nakd_interface *,
                               struct rtnl_link *link);

static intf_update_cb _intf_update_cbs[] = {
    _carrier_update,
    NULL
};

int nakd_update_iface_config(enum nakd_interface_id id,
        nakd_uci_option_foreach_cb cb, void *priv) {
    /* Find interface tag, execute callback. */
    int tags_found = nakd_uci_option_foreach(
                  nakd_uci_interface_tag[id],
                                   cb, priv);
    if (tags_found < 0) {
        nakd_log(L_CRIT, "Couldn't read UCI interface tags.");
    } else if (!tags_found) {
        nakd_log(L_WARNING, "No UCI \"%s\" interface tags found.",
                                nakd_uci_interface_tag[id]);
    } else if (tags_found != 1) {
        nakd_log(L_WARNING, "Found more than one \"%s\" interface tag, "
                      "using interface \"%s\".", nakd_uci_interface_tag[
                                          id], nakd_interface_type[id]);
    } else {
        nakd_log(L_DEBUG, "Found \"%s\" interface tag. (intf: %s)",
                                        nakd_uci_interface_tag[id],
                                          nakd_interface_type[id]);
    }
    return tags_found;
}

static int _disable_interface(struct uci_option *option, void *priv) {
    struct nakd_interface *intf = priv;
    struct uci_section *ifs = option->section;
    struct uci_context *ctx = ifs->package->ctx;

    nakd_assert(ifs != NULL);
    nakd_assert(ctx != NULL);

    struct uci_ptr disabled_ptr = {
        .package = ifs->package->e.name,
        .section = ifs->e.name,
        .option = "disabled",
        .value = "1"
    };
    nakd_assert(!uci_set(ctx, &disabled_ptr));
    return 0;
}

int nakd_disable_interface(enum nakd_interface_id id) {
    int status = 0;

    nakd_log(L_INFO, "Disabling %s.", nakd_interface_type[id]);
    pthread_mutex_lock(&_netintf_mutex);

    if (nakd_update_iface_config(id, _disable_interface,
                                           NULL) != 1) {
        status = 1;
        goto unlock;
    }

unlock:
    pthread_mutex_unlock(&_netintf_mutex);
    return status;
}

static int _interface_disabled(struct uci_option *option, void *priv) {
    struct nakd_interface *intf = priv;
    struct uci_section *ifs = option->section;
    struct uci_context *ctx = ifs->package->ctx;

    nakd_assert(ifs != NULL);
    nakd_assert(ctx != NULL);

    const char *disabled = uci_lookup_option_string(ctx, ifs, "disabled");
    if (disabled == NULL) {
        *(int *)(priv) = 0; /* default */
        return 0;
    }

    *(int *)(priv) = atoi(disabled);
    return 0;
}

int nakd_interface_disabled(enum nakd_interface_id id) {
    int status;
    pthread_mutex_lock(&_netintf_mutex);
    if (nakd_update_iface_config(id, _interface_disabled,
                                         &status) != 1) {
        status = -1;
        goto unlock;
    }

unlock:
    pthread_mutex_unlock(&_netintf_mutex);
    return status;
}

static int _read_intf_config(struct uci_option *option, void *priv) {
    struct nakd_interface *intf = priv;
    struct uci_section *ifs = option->section;
    struct uci_context *ctx = ifs->package->ctx;
    const char *ifname = uci_lookup_option_string(ctx, ifs, "ifname");
    if (ifname == NULL) {
        nakd_log(L_WARNING, "UCI interface tag found, but there's no ifname "
                                                                 "defined.");
        return 1;
    }
    intf->name = strdup(ifname);
    return 0;
}

static void _read_config(void) {
    /* update interface->name with tags found in UCI */
    for (struct nakd_interface *intf = _interfaces;
          intf != ARRAY_END(_interfaces); intf++) {
        nakd_update_iface_config(intf->id, _read_intf_config, intf);
    }
}

static const char *__interface_name(enum nakd_interface_id id) {
    for (struct nakd_interface *intf = _interfaces;
          intf != ARRAY_END(_interfaces); intf++) {
        if (intf->id == id)
            return intf->name;
    }
    nakd_log(L_WARNING, "Returning default interface name for %s",
                                         nakd_interface_type[id]);
    return nakd_interface_default[id];
}

const char *nakd_interface_name(enum nakd_interface_id id) {
    pthread_mutex_lock(&_netintf_mutex);
    const char *name = __interface_name(id);
    pthread_mutex_unlock(&_netintf_mutex);
    return name;
}

int nakd_carrier_present(enum nakd_interface_id id) {
    struct nakd_interface *intf = nakd_iface_from_id(id);
    if (intf == NULL) {
        nakd_log(L_CRIT, "No such interface id: %d", id);
        return -1;
    }

    pthread_mutex_lock(&_netintf_mutex);
    int status = intf->carrier_state;
    pthread_mutex_unlock(&_netintf_mutex);
    return status;
}

static void _handle_update(struct nl_object *obj, void *priv) {
    const char *nl_type = nl_object_get_type(obj);
    if (strcmp(nl_type, "route/link"))
        return;

    struct rtnl_link *link = (struct rtnl_link *)(obj);
    const char *link_name = rtnl_link_get_name(link);
    struct nakd_interface *iface = nakd_iface_from_name_string(link_name);
    if (iface == NULL) {
        nakd_log(L_DEBUG, "Unknown interface: %s", link_name);
        return;
    }

    for (intf_update_cb *cb = _intf_update_cbs; *cb != NULL; cb++)
        (*cb)(iface, link);
}

static void _update_cb(struct nl_cache *cache, struct nl_object *obj,
                                            int action, void *priv) {
    _handle_update(obj, NULL);
}

static void _netlink_loop(struct nakd_thread *thread) {
    while (!_shutdown) {
        int err = nl_cache_mngr_poll(_manager, 1000);
        if (err < 0 && err != -NLE_INTR)
            nakd_log(L_CRIT, "netlink: polling failed: %s", nl_geterror(err));
    }    
}

static void _netlink_shutdown(struct nakd_thread *thread) {
    _shutdown = 1;
}

static int _netintf_init(void) {
    pthread_mutex_init(&_netintf_mutex, NULL);
    _read_config();

    nakd_assert(!nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE,
                                                              &_manager));
    nakd_assert(!nl_cache_mngr_add(_manager, "route/link", &_update_cb,
                                                       NULL, &_cache));
    nakd_assert(!nakd_thread_create_joinable(_netlink_loop,
               _netlink_shutdown, NULL, &_netlink_thread));

    /* set initial interface states */
    nl_cache_foreach(_cache, _handle_update, NULL);

    return 0;
}

static int _netintf_cleanup(void) {
    nl_cache_mngr_free(_manager);
    pthread_mutex_destroy(&_netintf_mutex);
    return 0;
}

struct nakd_interface *nakd_iface_from_type_string(const char *iface) {
    for (const char **istr = nakd_interface_type; *istr != NULL; istr++) {
        if (!strcasecmp(iface, *istr)) {
            enum nakd_interface_id id = (enum nakd_interface_id)(istr
                                        - nakd_interface_type);
            for (struct nakd_interface *intf = _interfaces;
                            intf != ARRAY_END(_interfaces);
                                                  intf++) {
                if (intf->id == id)
                    return intf;
            }
            break;
        }
    }
    return NULL;
}

struct nakd_interface *nakd_iface_from_name_string(const char *iface) {
    for (struct nakd_interface *intf = _interfaces;
          intf != ARRAY_END(_interfaces); intf++) {
        if (intf->name == NULL)
            continue;
        if (!strcasecmp(iface, intf->name))
            return intf;
    }
    return NULL;
}

struct nakd_interface *nakd_iface_from_id(enum nakd_interface_id ifn) {
    for (struct nakd_interface *intf = _interfaces;
          intf != ARRAY_END(_interfaces); intf++) {
        if (intf->id == ifn)
            return intf;
    }
    return NULL;
}

static json_object *__build_interface_state(void) {
    json_object *jresult = json_object_new_array();
    nakd_assert(jresult != NULL);

    for (struct nakd_interface *intf = _interfaces;
          intf != ARRAY_END(_interfaces); intf++) {
        if (intf->name == NULL) 
            continue;

        json_object *jintf = json_object_new_object();
        json_object *jiname = json_object_new_string(intf->name);
        nakd_assert(jintf != NULL && jiname != NULL);

        json_object *jcarrier = json_object_new_boolean(
                                   intf->carrier_state); 
        json_object_object_add(jintf, "name", jiname);
        json_object_object_add(jintf, "carrier", jcarrier);
        json_object_array_add(jresult, jintf);
    }
    return jresult;
}

json_object *cmd_interface_state(json_object *jcmd, void *arg) {
    pthread_mutex_lock(&_netintf_mutex);
    json_object *jresponse = nakd_jsonrpc_response_success(jcmd,
                                      __build_interface_state());
unlock:    
    pthread_mutex_unlock(&_netintf_mutex);
    return jresponse;
}

static struct nakd_module module_netintf = {
    .name = "netintf",
    .deps = (const char *[]){ "uci", "event", NULL },
    .init = _netintf_init,
    .cleanup = _netintf_cleanup
};
NAKD_DECLARE_MODULE(module_netintf);

static struct nakd_command interfaces = {
    .name = "interfaces",
    .desc = "Returns current network interface state.",
    .usage = "{\"jsonrpc\": \"2.0\", \"method\": \"interfaces\", \"id\": 42}",
    .handler = cmd_interface_state,
    .access = ACCESS_USER,
    .module = &module_netintf
};
NAKD_DECLARE_COMMAND(interfaces);
