#!/bin/sh
curl -o /dev/null --silent --head --write-out '%{http_code}\n' http://clients3.google.com/generate_204 | awk '{if ($0 == "204") exit 0; exit 1;}'
