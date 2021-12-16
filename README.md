# BehavIoT
Analyzing change in behavior of IOT devices

![TpLink Bulb bar graph analysis](https://github.com/sidvsukhi/BehavIoT/blob/main/tplink_analyze.png?raw=true)

Instructions-

Directory Explained-
You can find the device file here: /traffic/devices.txt
You can find the network traffic for each device in this directory:/traffic/by-name
Inside the directory of every device you will find some files containing misc information (such as the mac address).
What you need is the content of the directory "unctrl", which contains many "pcap" files, organized by date, for when the device actually produced network traffic.

What are .pcap files? <br>
pcap files generated using wireshark, contain packet data

MonIOTr server directory explained-<br>
/traffic-<br>
	by-all<br>
	by-mac<br>
	by-ip<br>
	by-name (network traffic of each device by name)<br>
	devices.txt (devices list)

Scripts Use Explained-
1. Python script
	It extracts domain name (and their time epoch) from dns/tls records.
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
3. pandas
4. mathplotlib

Important Files-
1. .model - this file contains ipv6 addresses of all domain names
2. s2_decode_dns_tls.py- Extracts IP addresses and Domain names from packets (pcap files).
3. output.py file- shows device name, IPS, Domain Names and Linux Epoch of Sending and Receiving packet.
4. Analyze_washer.ipynb- analyzing IP addresses and domain names and examining bar graphs and venn diagram
5. extractProtocol.py- Extract protocols from every packet
6. AnalyzeProtocols.ipynb- analyzing protocol information