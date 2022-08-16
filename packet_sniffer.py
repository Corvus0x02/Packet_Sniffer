#!/usr/bin/env python3
#import http

import scapy.all as scapy
from scapy.layers.http import *

#store specifies where scapy should store this sniffed information. Defaults to in-memory
#prn specifies a function to run with each packet sniffed
#filter can be udp, tcp, arp, etc. Ports with "port 21", "port 22", etc.
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    #Sniff for HTTP POST Requests
    if packet.haslayer(HTTPRequest):
        if packet.haslayer(Raw):
            print(packet.show())
            print(packet[Raw].load)
    #Sniff for Cookies in HTTP Responses
    #if packet.haslayer(HTTPResponse):
sniff("eth0")