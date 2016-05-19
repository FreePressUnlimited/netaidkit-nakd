#!/bin/sh

# reset stage
/usr/share/nakd/scripts/set_stage.sh 0;

# reset password
echo "" > /nak/webapp/data/pass

# iptables flushing
/usr/share/nakd/scripts/reset_iptables.sh

# reset captive portal dns
echo "address=/#/192.168.101.1" > /etc/dnsmasq.conf;
/etc/init.d/dnsmasq restart

# reset firewall rules
uci set firewall.@redirect[0].enabled=1
uci set firewall.@redirect[1].enabled=0
uci set firewall.@redirect[2].enabled=0
uci set firewall.@forwarding[0].enabled=0
uci set firewall.@forwarding[1].enabled=0;
killall -9 openvpn
uci commit firewall
/etc/init.d/firewall restart

# reset wifi AP
uci set wireless.@wifi-iface[1].ssid='NETAIDKIT';
uci set wireless.@wifi-iface[1].key='netaidkit';
uci set wireless.@wifi-iface[1].hidden='0';


# reset uplink wifi
uci set wireless.@wifi-iface[0].disabled=1
uci set wireless.@wifi-iface[0].ssid='';
uci set wireless.@wifi-iface[0].encryption='';
uci set wireless.@wifi-iface[0].key='';
uci commit wireless
wifi
