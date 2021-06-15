#!/bin/bash

#variables
br_name="br0"
#eth_if="eth2 eth3 eth4"
eth_if="enp3s0f1 enp3s0f0"

#bring all interfaces down
for file in ${eth_if} ${br_name};
do 
	echo "interface ${file} down";
	ip link set dev ${file} down;
	sleep 1;
done;

#detach interfaces from bridge
for file in ${eth_if};
do
	echo "detaching ${file} from ${br_name}";
	brctl delif ${br_name} ${file};
	echo "promisc mode for ${file} off"
	ip link set dev ${file} promisc off;
done;

#delete the bridge
echo "deleting bridge instance..."
brctl delbr ${br_name};

echo "done.";

