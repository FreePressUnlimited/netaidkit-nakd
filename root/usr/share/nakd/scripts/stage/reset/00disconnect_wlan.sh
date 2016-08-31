#!/bin/sh
echo '{"jsonrpc": "2.0", "method": "wlan_disconnect", "id": 1}' | socat - UNIX-CONNECT:/run/nakd/nakd.sock
