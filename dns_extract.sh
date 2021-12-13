#!bin/bash
###
# This component for direct file to dns txt
### 

while read device
do 
	echo $device
	ls /traffic/by-name/$device/unctrl/2021-08-10*.pcap >> dns_candidates_activity.txt
	ls /traffic/by-name/$device/unctrl/2021-08-0*.pcap >> dns_candidates_activity.txt
    ls /traffic/by-name/$device/unctrl/2021-07-3*.pcap >> dns_candidates_activity.txt
	ls /traffic/by-name/$device/unctrl/2021-07-2*.pcap >> dns_candidates_activity.txt
done < 2021devices.txt

###########
# Extract DNS / TLS
###
out_dir=/home/tianrui/autodns
new_file=''

while read file
do 
	# echo $file | cut -d '/' -f 6
	device=$(echo $file|cut -d '/' -f 4)
	new_file=$(echo $file|cut -d '/' -f 6)
	
	# if [ $device == "echodot3c" ]; then
	echo $new_file $device
	mkdir -p $out_dir/$device/unctrl
	tshark -r $file -Y 'dns||dns.a||ssl.handshake.extensions_server_name' -w $out_dir/$device/unctrl/$new_file -F pcap
	# fi
done < dns_candidates_activity.txt

###
# Merge files if necessary
# ##
# while read file
# do 
# 	device=$(echo $file|cut -d '/' -f 4)
# 	# echo $device
# 	if [ ! -f $out_dir/$device/unctrl/$device.pcap ]; then
# 		mergecap $out_dir/$device/unctrl/*.pcap -w $out_dir/$device/unctrl/$device.pcap
# 	fi
# done < dns_candidates_activity.txt



