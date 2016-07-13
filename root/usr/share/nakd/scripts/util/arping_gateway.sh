#!/bin/sh
arping -f -q -w 3 -I $1 $(./util/gateway_ip.sh)
