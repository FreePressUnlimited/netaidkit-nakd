#!/bin/sh
# daemon config
cp -raf /usr/share/nakd/defaults/* /
# project config
cp -raf /usr/share/nak/defaults/* /
# uploaded openvpn certificates
rm -rf /nak/ovpn/upload/*
# webapp configuration
rm -rf /nak/webapp/data/*
