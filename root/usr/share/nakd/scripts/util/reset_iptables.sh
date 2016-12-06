#!/bin/sh

/etc/init.d/firewall stop

# Flush the iptables
iptables -F INPUT
iptables -F OUTPUT 
iptables -t nat -F

# Rules against (kernel bug) transproxy state leaks
# https://lists.torproject.org/pipermail/tor-talk/2014-March/032507.html
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP

/etc/init.d/firewall start
