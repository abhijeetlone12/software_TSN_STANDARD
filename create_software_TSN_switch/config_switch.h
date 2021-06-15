#!/bin/bash

modprobe br_netfilter
#variables
br_name="br0"
#eth_interfaces="eth2 eth3 eth4";
eth_interfaces="enp3s0f0 enp3s0f1";

#create bridge
echo "creating bridge"
brctl addbr ${br_name}

#promisc mode
echo "promisc mode on for ${eth_interfaces}"
for file in ${eth_interfaces};
do
	ip link set dev ${file} promisc on;
	sleep 1;
done;

#bring up interfaces
echo "bringing up interfaces ${eth_interfaces}"
for file in ${eth_interfaces};
do
	ip link set dev ${file} up;
	sleep 1;
done;

#add interfaces to bridge
echo "adding interfaces to the bridge"
brctl addif ${br_name} ${eth_interfaces}

sleep 2;

#bring up the bridge
echo "bringing up the bridge"
ip link set dev ${br_name} up

# bridge config
echo "Configuring..."
for file in ${eth_interfaces} ${br_name}; 
do 
	echo "==============================================="
	echo "printing initial values for ${file}..."
	echo "/proc/sys/net/ipv4/conf/${file}/proxy_arp = $(cat /proc/sys/net/ipv4/conf/${file}/proxy_arp)";
	echo "/proc/sys/net/ipv4/conf/${file}/forwarding = $(cat /proc/sys/net/ipv4/conf/${file}/forwarding)";
	echo "/proc/sys/net/ipv4/conf/${file}/mc_forwarding = $(cat /proc/sys/net/ipv4/conf/${file}/mc_forwarding )";
	echo "/proc/sys/net/ipv4/conf/${file}/bc_forwrding = $(cat /proc/sys/net/ipv4/conf/${file}/bc_forwarding)"

	echo "writing values for ${file}..."
	echo 1 > /proc/sys/net/ipv4/conf/${file}/proxy_arp;
	echo 1 > /proc/sys/net/ipv4/conf/${file}/forwarding;
	echo 1 > /proc/sys/net/ipv4/conf/${file}/mc_forwarding;
	echo 1 > /proc/sys/net/ipv4/conf/${file}/bc_forwarding;

        echo "printg values..."
	echo "/proc/sys/net/ipv4/conf/${file}/proxy_arp = $(cat /proc/sys/net/ipv4/conf/${file}/proxy_arp)";
        echo "/proc/sys/net/ipv4/conf/${file}/forwarding = $(cat /proc/sys/net/ipv4/conf/${file}/forwarding)";
        echo "/proc/sys/net/ipv4/conf/${file}/mc_forwarding = $(cat /proc/sys/net/ipv4/conf/${file}/mc_forwarding)";
        echo "/proc/sys/net/ipv4/conf/${file}/bc_forwrding = $(cat /proc/sys/net/ipv4/conf/${file}/bc_forwarding)";
	echo "===============================================";
done;

echo "===============================================";
echo "printing initial value..."
echo "/proc/sys/net/ipv4/ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"
echo "/proc/sys/net/bridge/bridge-nf-call-iptables = $(cat /proc/sys/net/bridge/bridge-nf-call-iptables)"
echo "/proc/sys/net/bridge/bridge-nf-call-arptables = $(cat /proc/sys/net/bridge/bridge-nf-call-iptables)"
echo "/sys/devices/virtual/net/${br_name}/bridge/multicast_querier = $(cat /sys/devices/virtual/net/${br_name}/bridge/multicast_querier)"
echo "/sys/devices/virtual/net/${br_name}/bridge/multicast_snooping = $(cat /sys/devices/virtual/net/${br_name}/bridge/multicast_snooping)"

echo "writing value..."
echo 1 > /proc/sys/net/ipv4/ip_forward;
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables;
echo 0 > /proc/sys/net/bridge/bridge-nf-call-arptables;
echo 0 > /sys/devices/virtual/net/${br_name}/bridge/multicast_querier;
echo 0 > /sys/devices/virtual/net/${br_name}/bridge/multicast_snooping;

echo "/proc/sys/net/ipv4/ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"
echo "/proc/sys/net/bridge/bridge-nf-call-iptables = $(cat /proc/sys/net/bridge/bridge-nf-call-iptables)"
echo "/proc/sys/net/bridge/bridge-nf-call-arptables = $(cat /proc/sys/net/bridge/bridge-nf-call-iptables)"
echo "/sys/devices/virtual/net/${br_name}/bridge/multicast_querier = $(cat /sys/devices/virtual/net/${br_name}/bridge/multicast_querier)"
echo "/sys/devices/virtual/net/${br_name}/bridge/multicast_snooping = $(cat /sys/devices/virtual/net/${br_name}/bridge/multicast_snooping)"
echo "===============================================";

echo "done."

