# BehavIoT
Analyzing change in behavior of IOT devices

Instructions-

Directory Explained-
You can find the device file here: /traffic/devices.txt
You can find the network traffic for each device in this directory:/traffic/by-name
Inside the directory of every device you will find some files containing misc information (such as the mac address).
What you need is the content of the directory "unctrl", which contains many "pcap" files, organized by date, for when the device actually produced network traffic.

MonIOTr server directory explained-
/traffic-
	by-all
	by-mac
	by-ip
	by-name- network traffic of each device by name
	devices.txt- devices list
	mitm
	tagged

Scripts Use Explained-
1. Python script
	Its to extract domain name (and their time epoch) from dns/tls records.
	needs the list of pcap file you’re analyzing as the input.
	run it on your local machine. You can use scp to copy files to your computer.
2. Shell script
	The shell script is to extract dns/tls records from raw pcap files.
	needs an input file with list of devices
	run the shell script on the mon(iot)r server.

Install ubuntu packages- 
1. tshark
2. whois

Python modules installed and their uses-
1. whois- to get registration information about domain name/ip address
2. numpy
3. constants

What are .pcap files?
pcap files generated using wireshark, contain packet data 

.model - this file contains ipv6 addresses of all domain names


output.py file- shows device name, IPS, Domain Names and Linux Epoch of Sending and Receiving packet.