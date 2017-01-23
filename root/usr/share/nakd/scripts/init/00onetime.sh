#!/bin/sh
/usr/share/nakd/scripts/util/restore_defaults.sh

# Make sure /run/tor exists and is accessible only by "tor" user,
# otherwise Tor daemon will terminate.                           
mkdir -p /run/tor
chown tor:tor /run/tor
chmod 700 /run/tor

rm /usr/share/nakd/scripts/init/00onetime.sh
