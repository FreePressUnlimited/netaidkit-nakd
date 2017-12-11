#!/bin/sh
# kill any frozen ntpclient instances that might block the initscript
killall ntpclient 
/etc/init.d/sysntpd restart
