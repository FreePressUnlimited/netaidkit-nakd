#!/bin/sh
echo '{"jsonrpc": "2.0", "method": "stage_set", "params": "reset", "id": 1}' | socat - UNIX-CONNECT:/run/nakd/nakd.sock
