#!/bin/sh

uci set firewall.@redirect[0].enabled=0;
uci commit firewall;
/etc/init.d/firewall restart;

echo > /etc/dnsmasq.conf
/etc/init.d/dnsmasq restart

/etc/init.d/sysntpd restart
