#!/usr/bin/python

"""
Honeypot made in Python 2.7 with Scapy.
Description: Displays all ports as OPEN.
Author: Alexander Kravchenko.

"""
import uuid
from scapy.all import *

# Get your MAC address with help of uuid library
my_mac = ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0, 8 * 6, 8)][::-1])
# SSH banner for all SYNs
banner = "SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2\n"


def captureSniff():
        #Sniff all TCP scans and proceed them to sendSyn function.
        sniff(filter="tcp and portrange 1-65535", prn=sendSyn)


#Send SYN-ACK for all ports
def sendSyn(pkt):
        if pkt.haslayer("Ethernet"):
                # if mac address is the same, abort.
                if my_mac.lower() == pkt['Ethernet'].src:
                        return

        if pkt.haslayer("IP") and pkt.haslayer("TCP"):
                # Syn scan.
                if pkt["TCP"].flags == 2:
                        d = pkt["IP"].src
                        s = pkt["IP"].dst
                        dp = pkt["TCP"].sport
                        sp = pkt["TCP"].dport
                        a = pkt["TCP"].seq + 1
                        send(IP(dst=d, src=s) / TCP(dport=dp, sport=sp, ack=a, flags="SA")/Raw(load=banner))

                # Response for Full Three Way Handshake scan (Ex. -sT) or nmap from MAC OS.
                if pkt["TCP"].flags == 1:
                        a = pkt["TCP"].seq + 1
                        send(IP(dst=d, src=s) / TCP(dport=dp, sport=sp, ack=a, flags="A")/Raw(load=banner))


try:
        captureSniff()

except:
        exit(0)