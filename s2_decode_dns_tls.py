import sys
import os
import whois
import ipaddress
import numpy as np
import constants as c
import pickle
import collections
from collections import Counter
from copy import deepcopy


"""
This file extracts ip-host tuple from dns and tls messages. 

"""
#is_error is either 0 or 1
def print_usage(is_error):
    print(c.DEC_RAW_USAGE, file=sys.stderr) if is_error else print(c.DEC_RAW_USAGE)
    exit(is_error)

def hostname_extract(infiles, dev_name):
    ip_host = {} # dictionary of destination IP to hostname

    for in_pcap in infiles:
        # file contains hosts and ips in format [hostname]\t[ip,ip2,ip3...]
        hosts = str(os.popen("tshark -r %s -Y \"dns&&dns.a\" -T fields -e dns.qry.name -e dns.a -e frame.time_epoch"
                            % in_pcap).read()).splitlines()
        tls_hosts = str(os.popen("tshark -r %s -Y \"tls.handshake.extensions_server_name\" -T fields -e tls.handshake.extensions_server_name -e ip.dst -e frame.time_epoch"
                            % in_pcap).read()).splitlines()
        # make dictionary of ip to host from DNS requests
        
        for line in hosts: # load ip_host
            line = line.split("\t") # host_name, ips, time_epoch
            ips = line[1].split(",")
            for ip in ips:
                # if ip in ip_host and ip_host[ip] != line[0]:
                    # print(ip, ip_host[ip], line[0], line[-1]) # check if some ips would be dynamically used by multiple domains. 
                if ip in ip_host:
                    ip_host[ip].append((line[0],line[-1]))
                else:
                    ip_host[ip] = [(line[0],line[-1])]
    
        for line in tls_hosts:
            line = line.split("\t")
            ips = line[1].split(",")
            for ip in ips:
                if ip in ip_host:
                    ip_host[ip].append((line[0],line[-1]))
                else:
                    ip_host[ip] = [(line[0],line[-1])]
    print(dev_name) # , ip_host

    return ip_host

def main():
    [ print_usage(0) for arg in sys.argv if arg in ("-h", "--help") ]

    print("Running %s..." % sys.argv[0])

    # error checking
    # check for 2 or 3 arguments
    # if len(sys.argv) != 3 and len(sys.argv) != 4:
    #     print(c.WRONG_NUM_ARGS % (2, (len(sys.argv) - 1)))
    #     print_usage(1)

    in_txt = sys.argv[1]
    # out_dir = sys.argv[2]
    # str_num_proc = sys.argv[3] if len(sys.argv) == 4 else "5"

    #check in_txt
    errors = False
    if not in_txt.endswith(".txt"):
        errors = True
        print(c.WRONG_EXT % ("Input text file", "text (.txt)", in_txt), file=sys.stderr)
    elif not os.path.isfile(in_txt):
        errors = True
        print(c.INVAL % ("Input text file", in_txt, "file"), file=sys.stderr)
    elif not os.access(in_txt, os.R_OK):
        errors = True
        print(c.NO_PERM % ("input text file", in_txt, "read"), file=sys.stderr)



    if errors:
        print_usage(1)
    #end error checking

    print("Input file located in: %s\n" % (in_txt))


    dns_files = {}

    with open(in_txt, "r") as f:
        for pcap in f:
            pcap = pcap.strip()
            if not pcap.endswith(".pcap"):
                print(c.WRONG_EXT % ("Input pcaps", "pcap (.pcap)", pcap))
            elif not os.path.isfile(pcap):
                print(c.INVAL % ("Input pcap", pcap, "file"))
            elif not os.access(pcap, os.R_OK):
                print(c.NO_PERM % ("input pcap", pcap, "read"))
            else:


                dir_name = os.path.dirname(pcap)
                dev_name = os.path.basename(os.path.dirname(dir_name))
                # if dev_name != 'echodot3a':
                #     continue

                ## only accept merged file, not origial pcap file
                # if os.path.basename(pcap).startswith('2021'):
                #      continue
                
                print(pcap)
                if dev_name in dns_files:
                    dns_files[dev_name].append(pcap)
                else:
                    dns_files[dev_name] = [pcap]
    ip_hosts_all = {}
    for dev in dns_files.keys():
        ip_hosts_all[dev] = hostname_extract(dns_files[dev],dev)


    out_dir = '/home/dell/NEU/BehavIOT/dns/ikettle/Aug2021'
    model_file = '%s/testing_for_scipt.txt' %  out_dir
    # ip_hosts['echodot3c'] = ip_hosts_all['echodot3c']
    # model_file = '/home/ubuntu/Behaviot/event_inference/ip_host/ip_host_idle.model'

    pickle.dump(ip_hosts_all, open(model_file, 'wb'))

    ip_hosts = pickle.load(open(model_file, 'rb'))
    print(ip_hosts)
    with open("./ikettle/Aug2021/output.py", "w") as text_file:
        text_file.write(str(ip_hosts))
    # ip_hosts_all = pickle.load(open(model_file, 'rb'))


if __name__ == "__main__":
    main()

