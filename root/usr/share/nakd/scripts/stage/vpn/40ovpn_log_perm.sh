#!/bin/sh
# openvpn daemon will append to this file
touch /var/log/openvpn.log
chgrp www-data /var/log/openvpn.log
chmod g+rw /var/log/openvpn.log
