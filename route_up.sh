#!/bin/sh

table_id=2`echo $dev | cut -c 4-24`
echo "$dev : $ifconfig_local -> $ifconfig_remote gw: $route_vpn_gateway, table_id: $table_id"


ip route add default via $route_vpn_gateway dev $dev table $table_id
ip rule add from $ifconfig_local table $table_id
ip rule add to $route_vpn_gateway table $table_id
ip route flush cache

exit 0
