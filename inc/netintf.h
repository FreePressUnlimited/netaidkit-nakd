#ifndef NAKD_NETINTF_H
#define NAKD_NETINTF_H
#include <json-c/json.h>
#include "nak_uci.h"
#include "event.h"

enum nakd_interface_id {
    NAKD_LAN,
    NAKD_WAN,
    NAKD_WLAN,
    NAKD_AP,
    NAKD_INTF_MAX
};

enum nakd_interface_id_carrier {
    NAKD_CARRIER_UP,
    NAKD_CARRIER_DOWN,
    NAKD_CARRIER_MAX
};

struct nakd_interface {
    enum nakd_interface_id id;
    /* eg. eth1, filled by netintf code */
    char *name;

    enum nakd_interface_id_carrier carrier_state;
    enum nakd_event carrier_up_event;
    enum nakd_event carrier_down_event;
};

int nakd_update_iface_config(enum nakd_interface_id id,
         nakd_uci_option_foreach_cb cb, void *priv);
int nakd_disable_interface(enum nakd_interface_id id);
int nakd_interface_disabled(enum nakd_interface_id id);
int nakd_carrier_present(enum nakd_interface_id id);

const char *nakd_interface_name(enum nakd_interface_id id);
struct nakd_interface *nakd_iface_from_type_string(const char *iface);
struct nakd_interface *nakd_iface_from_name_string(const char *iface);
struct nakd_interface *nakd_iface_from_id(enum nakd_interface_id iface);

json_object *cmd_interface_state(json_object *jcmd, void *arg);

extern const char *nakd_uci_interface_tag[];
extern const char *nakd_interface_type[];
extern const char *nakd_interface_default[];

#endif
