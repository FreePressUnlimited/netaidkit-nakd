#!/bin/sh
DNSMASQ_CONF=/etc/dnsmasq.conf

# Adds pushed DNS server to dnsmasq config and restarts it.
IFS='{}'
for env in $(cat /proc/self/environ | tr '\0' '{}'); do
	key=$(echo $env | awk -vRS= -vFS="=" '{ print $1 }')
	value=$(echo $env | awk -vRS= -vFS="=" '{ print $2 }')

	echo $key | grep -q foreign_option_
	if [ $? -eq 0 ]; then
		option_type=$(echo $value | awk -vRS= '{ print $1 }')
		echo $option_type | grep -q dhcp-option
		if [ $? -eq 0 ]; then
			option=$(echo $value | awk -vRS= '{ print $2 }')
			echo $option | grep -q DNS
			if [ $? -eq 0 ]; then
                # Remove all other upstream servers
                sed -i "/^server /d" $DNSMASQ_CONF

				value=$(echo $value | awk -vRS= '{ print $3 }')
				echo server $value >> $DNSMASQ_CONF
				echo no-resolv >> $DNSMASQ_CONF

				/etc/init.d/dnsmasq restart
				exit 0
			fi
		fi
	fi
done

