#!/bin/sh
# daemon config
cp -raf /usr/share/nakd/defaults/* /
# device, firewall, network config
cp -raf /usr/share/nak/defaults/etc/config/* /etc/config/*
# uploaded openvpn certificates
rm -rf /nak/ovpn/upload/*
# webapp configuration
rm -rf /nak/webapp/data/*
