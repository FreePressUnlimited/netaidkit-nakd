#!/bin/sh

# Kill any running openvpn instances that might be left from a crashed
# session.
killall openvpn
sleep 1s
pgrep openvpn
if [ $? -ne 1 ]; then
    killall -9 openvpn
fi
