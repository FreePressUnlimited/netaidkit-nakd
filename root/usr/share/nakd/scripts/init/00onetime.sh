#!/bin/sh
cp /usr/share/nak/defaults/etc/config/firewall /etc/config/.
cp /usr/share/nak/defaults/etc/config/network /etc/config/.
cp /usr/share/nak/defaults/etc/config/wireless /etc/config/.
rm /usr/share/nakd/scripts/init/00onetime.sh
