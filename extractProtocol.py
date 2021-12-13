from scapy.all import *
import os
import re

in_txt = '/home/dell/NEU/BehavIOT/dns/ikettle/Sep2021/input.txt'

proDict = {'TCP':0, 'ARP':0, 'TLS':0, 'DHCP':0, 'EAPOL':0, 'UDP':0, 'ICMP':0, 'DNS':0, 'XID':0}
tlsDestination = {}

with open(in_txt, "r") as f:
    for pcap in f:
        print(pcap)
        proList = str(os.popen("tshark -r %s"% pcap).read()).splitlines()
        for i in proList:
            if 'TCP' in i:
                proDict['TCP'] += 1
            elif 'ARP' in i:
                proDict['ARP'] += 1
            elif 'TLS' in i:
                proDict['TLS'] += 1
                ips = re.findall("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", i)
                if ips[-1] not in tlsDestination.keys():
                    tlsDestination[str(ips[-1])] = 1
                else:
                    tlsDestination[str(ips[-1])] += 1
            elif 'DHCP' in i:
                proDict['DHCP'] += 1
            elif 'EAPOL' in i:
                proDict['EAPOL'] += 1
            elif 'UDP' in i:
                proDict['UDP'] += 1
            elif 'ICMP' in i:
                proDict['ICMP'] += 1
            elif 'DNS' in i:
                proDict['DNS'] += 1
            elif 'XID' in i:
                proDict['XID'] += 1
            else:
                print(i)
print(tlsDestination)
print(proDict)
