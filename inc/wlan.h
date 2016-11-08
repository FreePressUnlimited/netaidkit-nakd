#ifndef NAKD_WLAN_H
#define NAKD_WLAN_H
#include <json-c/json.h>

int nakd_wlan_store_network(const char *ssid, const char *key,
                                             int autoconnect);

json_object *nakd_wlan_candidate(void);
int nakd_wlan_netcount(void);
int nakd_wlan_scan(void);
int nakd_wlan_connect(json_object *jnetwork);
int nakd_wlan_connecting(void);
int nakd_wlan_connected(void);
json_object *nakd_wlan_requested(void);
int nakd_wlan_disconnect(void);
json_object *nakd_wlan_current(void);
int nakd_wlan_in_range(const char *ssid);
int nakd_wlan_connection_uptime(void);
int nakd_wlan_network_count(void);

const char *nakd_net_key(json_object *jnetwork);
const char *nakd_net_ssid(json_object *jnetwork);
const char *nakd_net_encryption(json_object *jnetwork);
int nakd_net_disabled(json_object *jnetwork);
int nakd_net_hidden(json_object *jnetwork);

const char *nakd_wlan_interface_name(void);
const char *nakd_ap_interface_name(void);

void nakd_wlan_reset_stored(void);
int nakd_wlan_stored_netcount(void);

json_object *cmd_wlan_list_stored(json_object *jcmd, void *arg);
json_object *cmd_wlan_list(json_object *jcmd, void *arg);
json_object *cmd_wlan_scan(json_object *jcmd, void *arg);
json_object *cmd_wlan_connect(json_object *jcmd, void *arg);
json_object *cmd_configure_ap(json_object *jcmd, void *arg);

#endif
