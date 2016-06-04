#!/bin/sh
timeout -t 5 arping -f -q -w 5 -I $1 $(./util/gateway_ip.sh)
